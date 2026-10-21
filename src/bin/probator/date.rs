//! Civil-date math for the review crate's timestamps: one implementation of
//! Howard Hinnant's `civil_from_days` shared by every formatter, so a receipt
//! access date and a journal timestamp can never disagree about the calendar.
//!
//! The `probator` binary keeps its own copy in `src/records.rs` - the two are
//! separate crates. If a crate-boundary merge ever unites them, converge the
//! copies rather than keeping the algorithm alive twice.

/// Seconds since the unix epoch, 0 when the clock reports earlier.
pub(crate) fn epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Days since 1970-01-01 -> (year, month, day): 719468 days from 0000-03-01
/// to the epoch, then 400-year eras of 146097 days.
pub(crate) fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// `YYYY-MM-DD` for an epoch second - the receipt access date.
pub(crate) fn date_string(secs: i64) -> String {
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    format!("{year:04}-{month:02}-{day:02}")
}

/// `YYYY-MM-DDTHH:MM:SSZ` for an epoch second - the journal timestamp.
pub(crate) fn timestamp_string(secs: i64) -> String {
    let rest = secs.rem_euclid(86_400);
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        date_string(secs),
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_formatters_read_the_same_calendar() {
        // Epoch, a leap day, a pre-epoch negative, and a value far past today:
        // the date and timestamp paths must report the same civil fields.
        for secs in [0i64, 951_782_400, -86_401, 4_102_444_800] {
            let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
            let date = date_string(secs);
            let stamp = timestamp_string(secs);
            assert_eq!(date, format!("{year:04}-{month:02}-{day:02}"));
            assert_eq!(&stamp[..10], date, "timestamps disagree for {secs}");
            assert_eq!(stamp.len(), 20, "{stamp}");
        }
        assert_eq!(date_string(0), "1970-01-01");
        assert_eq!(date_string(951_782_400), "2000-02-29");
        assert_eq!(date_string(-86_400), "1969-12-31");
        assert_eq!(timestamp_string(-1), "1969-12-31T23:59:59Z");
        assert_eq!(timestamp_string(4_102_444_800), "2100-01-01T00:00:00Z");
    }
}
