//! The sealed run record Probator writes as `report.json`.
//!
//! The review crate writes one sealed report per
//! run rather than the main binary's multi-run ledger. That means the record
//! is a JSON object assembled by the review server and the gate: verdict,
//! findings, coverage and the review metadata all ride through unchanged.
//!
//! One field needs a rule of its own. `policy_signature` records whether an
//! audit-policy signature was active when the run happened, and records
//! sealed before the field existed do not carry it. Re-serializing such a
//! record must not materialize `"policy_signature": ""`, or the seal would
//! cover content the original record never had. The rule is expressed
//! as `#[serde(default, skip_serializing_if = "String::is_empty")]`; the
//! typed envelope below keeps the same behavior while preserving every
//! unknown report field in its original order.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A run record: the complete report plus the optional signature marker.
///
/// `#[serde(flatten)]` is deliberate. The report shape is owned by the
/// contract and the review server, not by this module, so everything this
/// type does not name must round-trip untouched. Only `policy_signature` is
/// lifted out, so an empty value can be skipped instead of written back.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Record {
    #[serde(flatten)]
    fields: Map<String, Value>,
    /// Whether the audit policy's signature held when the run happened.
    /// `valid`, `invalid` or `inactive`; empty means the record predates the
    /// field or no signature was armed. Absent on disk, never `""`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy_signature: String,
}

impl Record {
    /// Parse a report without losing fields this module does not name.
    pub fn from_value(value: Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }

    /// Re-emit the record. An empty signature is skipped exactly as the
    /// originating run-record attribute does, so old records keep their seal.
    pub fn into_value(self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

/// Round-trip a report through the record shape before it is sealed.
///
/// A value that cannot be represented as a record is returned untouched:
/// recording is observation, and a malformed record must not turn a verdict
/// into a failure. The conversion is only used on the path that is about to
/// write a fresh seal, where omitting an empty signature is the point.
pub fn normalize(value: Value) -> Value {
    let Ok(record) = Record::from_value(value.clone()) else {
        return value;
    };
    record.into_value().unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::{Record, normalize};
    use serde_json::json;

    /// A record sealed before the field existed has no `policy_signature`
    /// key. Round-tripping it must not add one, or `seal::valid` would no
    /// longer recompute over the stored bytes.
    #[test]
    fn an_absent_policy_signature_stays_absent_on_round_trip() {
        let mut raw = json!({"verdict": "pass", "findings": []});
        raw["seal_prev"] = json!("");
        raw["seal"] = json!(crate::seal::seal("", &raw));
        assert!(crate::seal::valid(&raw));

        let normalized = normalize(raw);
        assert!(
            normalized.get("policy_signature").is_none(),
            "an absent signature must not materialize: {normalized}"
        );
        assert!(
            crate::seal::valid(&normalized),
            "the seal must survive normalization: {normalized}"
        );
    }

    /// An explicit empty string carries no state; it is dropped so the next
    /// seal covers the same document a pre-field record would have.
    #[test]
    fn an_empty_policy_signature_is_omitted() {
        let normalized = normalize(json!({"verdict": "pass", "policy_signature": ""}));
        assert_eq!(normalized, json!({"verdict": "pass"}));
    }

    /// A real signature state is part of the record and must survive.
    #[test]
    fn a_recorded_policy_signature_is_preserved() {
        let normalized = normalize(json!({"verdict": "pass", "policy_signature": "valid"}));
        assert_eq!(normalized["policy_signature"], "valid");
        let record = Record::from_value(normalized).unwrap();
        assert_eq!(record.policy_signature, "valid");
    }

    /// Unknown report fields stay in their original order, so two records
    /// with the same content produce the same bytes.
    #[test]
    fn unknown_fields_keep_their_order() {
        let raw = json!({
            "verdict": "block",
            "summary": "one finding",
            "findings": [{"file": "src/lib.rs", "line": 7}],
            "coverage": {"structure": {"status": "reviewed", "reason": "read"}}
        });
        let normalized = normalize(raw.clone());
        assert_eq!(
            serde_json::to_string(&normalized).unwrap(),
            serde_json::to_string(&raw).unwrap()
        );
    }
}
