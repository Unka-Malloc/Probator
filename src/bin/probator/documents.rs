//! The catalogued official-document fetcher: Money Saver's fourth tool.
//!
//! The catalog is a closed whitelist - a fetch goes to a listed URL or
//! nowhere. Redirects are followed only inside the same authority: https,
//! same host, no credentials, no query - so a documentation page cannot
//! bounce the gate into an arbitrary origin. Ported from Money Saver's
//! `document` verb; the page extraction is byte-parity with its PageText,
//! pinned by the goldens.

use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::LazyLock;

/// Characters per document page - the same pagination contract as the
/// evidence verbs, for a page source only one checker serves.
pub const DOC_PAGE_CHARS: usize = 24000;

static TAG_NAME: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-zA-Z][a-zA-Z0-9]*").unwrap());

/// The UTC date a document was fetched. The Python original used the local
/// date; a receipt label must not depend on the machine's timezone.
pub(crate) fn today() -> String {
    crate::date::date_string(crate::date::epoch_secs())
}

/// HTML text extraction: `script` and `style` content is dropped, comments
/// and markup vanish, entity references decode, and the remaining text runs
/// are stripped and joined with newlines - HTMLParser(convert_charrefs=True)
/// with only handle_data collected.
pub fn page_text(raw: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut hidden = 0usize;
    let mut rest = raw;

    fn push_data(parts: &mut Vec<String>, hidden: usize, data: &str) {
        if hidden > 0 {
            return;
        }
        let text = decode_entities(data);
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            parts.push(trimmed.to_string());
        }
    }

    while let Some(at) = rest.find('<') {
        push_data(&mut parts, hidden, &rest[..at]);
        let after = &rest[at + 1..];
        // A `<` that opens no tag - literal text, as HTMLParser treats it.
        let Some(first) = after.chars().next() else {
            push_data(&mut parts, hidden, "<");
            rest = "";
            continue;
        };
        if !(first.is_ascii_alphabetic() || first == '/' || first == '!' || first == '?') {
            push_data(&mut parts, hidden, "<");
            rest = after;
            continue;
        }
        if let Some(comment) = after.strip_prefix("!--") {
            match comment.find("-->") {
                Some(end) => rest = &comment[end + 3..],
                None => rest = "",
            }
            continue;
        }
        // Find the closing `>` outside quoted attribute values.
        let mut end = None;
        let mut quote = None;
        for (index, c) in after.char_indices() {
            match (quote, c) {
                (Some(q), c) if c == q => quote = None,
                (None, '\'' | '"') => quote = Some(c),
                (None, '>') => {
                    end = Some(index);
                    break;
                }
                _ => {}
            }
        }
        let Some(end) = end else {
            rest = "";
            break;
        };
        let tag = &after[..end];
        let closing = tag.starts_with('/');
        let self_closing = tag.ends_with('/');
        let name = TAG_NAME
            .find(tag.trim_start_matches('/').trim_start())
            .map(|m| m.as_str().to_lowercase());
        if matches!(name.as_deref(), Some("script" | "style")) {
            if closing {
                hidden = hidden.saturating_sub(1);
            } else {
                hidden += 1;
                if self_closing {
                    hidden = hidden.saturating_sub(1);
                }
            }
        }
        rest = &after[end + 1..];
    }
    push_data(&mut parts, hidden, rest);
    parts.join("\n")
}

/// The standard named and numeric entities; anything unknown stays verbatim,
/// as HTMLParser leaves it.
fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let Some(end) = rest[at..].find(';') else {
            out.push_str(&rest[at..]);
            return out;
        };
        let entity = &rest[at + 1..at + end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            _ => entity
                .strip_prefix('#')
                .and_then(|number| {
                    if let Some(hex) = number.strip_prefix(['x', 'X']) {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        number.parse::<u32>().ok()
                    }
                })
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => out.push(c),
            None => {
                out.push('&');
                out.push_str(entity);
                out.push(';');
            }
        }
        rest = &rest[at + end + 1..];
    }
    out.push_str(rest);
    out
}

struct Split<'a> {
    scheme: &'a str,
    authority: &'a str,
    path: &'a str,
    query: Option<&'a str>,
}

/// The pieces of an absolute URL a redirect policy judges. Not a general
/// parser: anything it cannot read as `scheme://authority/path` is refused.
fn split(url: &str) -> Option<Split<'_>> {
    let (scheme, rest) = url.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let (path, query_and_fragment) = tail.split_at(path_end);
    let query = query_and_fragment
        .strip_prefix('?')
        .map(|q| q.split('#').next().unwrap_or(""));
    Some(Split {
        scheme,
        authority,
        path: if path.is_empty() { "/" } else { path },
        query,
    })
}

/// Resolve a redirect Location against the current URL: absolute, then
/// path-absolute, then relative to the current directory with `.`/`..`
/// segment resolution.
fn resolve(current: &str, location: &str) -> Option<String> {
    if location.contains("://") {
        return Some(location.to_string());
    }
    let base = split(current)?;
    if let Some(path) = location.strip_prefix('/') {
        return Some(format!("{}://{}/{}", base.scheme, base.authority, path));
    }
    let directory = base.path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
    let mut segments: Vec<&str> = directory.split('/').filter(|s| !s.is_empty()).collect();
    for segment in location.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    Some(format!(
        "{}://{}/{}",
        base.scheme,
        base.authority,
        segments.join("/")
    ))
}

/// The catalog is operator-owned: a redirect stays inside the same
/// authority, over https, carrying no credentials and no query.
fn redirect_allowed(from: &str, target: &str) -> bool {
    let (Some(from), Some(target)) = (split(from), split(target)) else {
        return false;
    };
    target.scheme == "https"
        && target.authority == from.authority
        && !target.authority.contains('@')
        && target.query.is_none()
}

/// Fetch one document, following policy-checked redirects. Returns the body
/// and whether it was HTML.
fn fetch(url: &str) -> Result<String, String> {
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .new_agent();
    let mut url = url.to_string();
    for _ in 0..10 {
        let mut response = agent
            .get(&url)
            .header("User-Agent", "Money-Saver/1.0")
            .header("Accept", "text/markdown,text/html,text/plain")
            .call()
            .map_err(|error| format!("The official document could not be fetched: {error}"))?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            let location = response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .ok_or("A redirect without a Location is not followable")?;
            let target = resolve(&url, location)
                .ok_or("A redirect without a resolvable Location is not followable")?;
            if !redirect_allowed(&url, &target) {
                return Err("Official documentation redirected outside its authority".to_string());
            }
            url = target;
            continue;
        }
        if status != 200 {
            return Err(format!("The official document answered HTTP {status}"));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|error| format!("The official document could not be read: {error}"))?;
        return Ok(if content_type.contains("html") {
            page_text(&body)
        } else {
            body
        });
    }
    Err("The official document redirects without settling".to_string())
}

pub struct Doc {
    pub url: String,
    pub accessed: String,
    pub content: String,
}

/// The catalog plus this review's fetched cache. The cache doubles as the
/// verdict's evidence trail: what was never fetched cannot be cited.
pub struct Documents {
    catalog: Map<String, Value>,
    cache: HashMap<String, Doc>,
}

impl Documents {
    pub fn new(catalog: Map<String, Value>) -> Documents {
        Documents {
            catalog,
            cache: HashMap::new(),
        }
    }

    /// The URLs of every fetched document - the set submit validation cites.
    pub fn fetched(&self) -> std::collections::HashSet<String> {
        self.cache.values().map(|doc| doc.url.clone()).collect()
    }

    /// Resolve a catalog key or listed URL to its key.
    pub fn resolve(&self, name: &str) -> Result<String, String> {
        if name.is_empty() {
            return Err("operation \"document\" requires a \"name\" argument".to_string());
        }
        if self.catalog.contains_key(name) {
            return Ok(name.to_string());
        }
        self.catalog
            .iter()
            .find(|(_, url)| url.as_str() == Some(name))
            .map(|(key, _)| key.clone())
            .ok_or_else(|| {
                format!(
                    "Choose an exact catalog key or listed URL. Keys: {}",
                    self.catalog.keys().cloned().collect::<Vec<_>>().join(", ")
                )
            })
    }

    pub fn is_cached(&self, key: &str) -> bool {
        self.cache.contains_key(key)
    }

    pub fn in_catalog(&self, key: &str) -> bool {
        self.catalog.contains_key(key)
    }

    /// Iterate the fetched documents (for the receipt's source list).
    pub fn cached_docs(&self) -> impl Iterator<Item = &Doc> {
        self.cache.values()
    }

    /// The full document, for persistence - never the paged reply.
    pub fn cached(&self, key: &str) -> Option<&Doc> {
        self.cache.get(key)
    }

    /// A persisted document rejoins the cache - a resumed run does not refetch.
    pub fn restore(&mut self, key: String, doc: Doc) {
        self.cache.insert(key, doc);
    }

    /// One catalog page: fetch on first use, then character-paged.
    pub fn get(&mut self, name: &str, offset: i64) -> Result<Value, String> {
        let key = self.resolve(name)?;
        if !self.cache.contains_key(&key) {
            let url = self.catalog[&key]
                .as_str()
                .ok_or("The catalog maps keys to URLs")?
                .to_string();
            let content = fetch(&url)?;
            self.cache.insert(
                key.clone(),
                Doc {
                    url,
                    accessed: today(),
                    content,
                },
            );
        }
        let doc = &self.cache[&key];
        let chars: Vec<char> = doc.content.chars().collect();
        let start = offset.max(0) as usize;
        let end = (start + DOC_PAGE_CHARS).min(chars.len());
        let page: String = chars[start.min(end)..end].iter().collect();
        Ok(json!({
            "url": doc.url,
            "accessed": doc.accessed,
            "content": page,
            "total_characters": chars.len(),
            "offset": start,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{Documents, page_text, redirect_allowed, resolve};
    use serde_json::{Map, Value, json};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn entities_and_markup_extract_like_the_engine() {
        // The goldens pin the full corpus; a few anchors stay inline.
        assert_eq!(page_text("<p>a &amp; b</p>"), "a & b");
        assert_eq!(page_text("<script>var x = 1;</script><p>kept</p>"), "kept");
        assert_eq!(page_text("<style>body {}</style>text"), "text");
        assert_eq!(
            page_text("plain &unknown; entity"),
            "plain &unknown; entity"
        );
        assert_eq!(page_text("<!-- gone -->visible"), "visible");
        // HTMLParser hands a bare `<` over as its own data chunk.
        assert_eq!(page_text("a < b"), "a\n<\nb");
    }

    #[test]
    fn extraction_matches_the_engine_goldens() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("review-parity");
        let cases: Vec<Value> = serde_json::from_str(
            &std::fs::read_to_string(dir.join("documents-cases.json")).unwrap(),
        )
        .unwrap();
        let expected: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("documents-expected.json")).unwrap(),
        )
        .unwrap();
        assert!(!cases.is_empty(), "the corpus must not be empty");
        for case in &cases {
            let name = case["name"].as_str().unwrap();
            assert_eq!(
                page_text(case["html"].as_str().unwrap()),
                expected[name].as_str().unwrap(),
                "case {name}"
            );
        }
    }

    #[test]
    fn redirect_resolution_and_policy() {
        let base = "https://docs.example.com/a/b/page";
        assert_eq!(
            resolve(base, "https://docs.example.com/x").as_deref(),
            Some("https://docs.example.com/x")
        );
        assert_eq!(
            resolve(base, "/rooted").as_deref(),
            Some("https://docs.example.com/rooted")
        );
        assert_eq!(
            resolve(base, "sibling").as_deref(),
            Some("https://docs.example.com/a/b/sibling")
        );
        assert_eq!(
            resolve(base, "../up").as_deref(),
            Some("https://docs.example.com/a/up")
        );
        assert!(redirect_allowed(base, "https://docs.example.com/other"));
        assert!(!redirect_allowed(base, "http://docs.example.com/other"));
        assert!(!redirect_allowed(
            base,
            "https://elsewhere.example.com/other"
        ));
        assert!(!redirect_allowed(
            base,
            "https://docs.example.com/other?token=1"
        ));
        assert!(!redirect_allowed(
            base,
            "https://user@docs.example.com/other"
        ));
        assert!(!redirect_allowed("not a url", "https://docs.example.com/x"));
    }

    /// A canned HTTP server: one canned route per path; connection-counted.
    struct Server {
        url: String,
        hits: std::sync::Arc<AtomicU64>,
    }

    fn serve(routes: Vec<(&'static str, &'static str)>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = std::sync::Arc::new(AtomicU64::new(0));
        let counter = hits.clone();
        // Detached: the process reaps it at exit; joining would block on the
        // listener forever.
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                counter.fetch_add(1, Ordering::Relaxed);
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let mut sink = String::new();
                while reader.read_line(&mut sink).is_ok_and(|n| n > 2) {}
                let route = routes
                    .iter()
                    .find(|(route, _)| route == &path)
                    .map(|(_, body)| *body);
                let response = match route {
                    None => {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    }
                    Some(body) if body.starts_with("30") => {
                        let (status, location) = body.split_once('\n').unwrap();
                        format!(
                            "HTTP/1.1 {status} Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    }
                    Some(body) => {
                        let (content_type, payload) =
                            body.split_once('\n').unwrap_or(("text/plain", ""));
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                            payload.len()
                        )
                    }
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Server {
            url: format!("http://127.0.0.1:{port}"),
            hits,
        }
    }

    #[test]
    fn fetch_cache_and_paging() {
        let markdown: &'static str =
            Box::leak(format!("text/markdown\n{}", "x".repeat(30)).into_boxed_str());
        let server = serve(vec![("/doc", markdown)]);
        let mut catalog = Map::new();
        catalog.insert("pricing".into(), json!(format!("{}/doc", server.url)));
        let mut docs = Documents::new(catalog);
        let first = docs.get("pricing", 0).unwrap();
        assert_eq!(first["url"], json!(format!("{}/doc", server.url)));
        assert_eq!(first["total_characters"], 30);
        // The cache answers the second page and the URL form: no new fetch.
        let _ = docs.get("pricing", 10).unwrap();
        let by_url = format!("{}/doc", server.url);
        let _ = docs.get(&by_url, 0).unwrap();
        assert_eq!(server.hits.load(Ordering::Relaxed), 1);
        assert!(docs.fetched().contains(&by_url));
        let missing = docs.get("nope", 0).unwrap_err();
        assert!(missing.contains("Choose an exact catalog key"), "{missing}");
    }

    #[test]
    fn redirect_policy_is_enforced() {
        let server = serve(vec![
            ("/loop", "301\n/loop"),
            ("/plain", "301\nhttp://127.0.0.1/other"), // http downgrade: refused
        ]);
        let mut catalog = Map::new();
        for key in ["loop", "plain", "gone"] {
            catalog.insert(key.into(), json!(format!("{}/{key}", server.url)));
        }
        let mut docs = Documents::new(catalog);
        assert!(
            docs.get("loop", 0)
                .unwrap_err()
                .contains("outside its authority")
        );
        assert!(
            docs.get("plain", 0)
                .unwrap_err()
                .contains("outside its authority")
        );
        assert!(docs.get("gone", 0).unwrap_err().contains("HTTP 404"));
    }
}
