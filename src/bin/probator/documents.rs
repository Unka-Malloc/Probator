//! The official-document fetcher: Money Saver's fourth tool.
//!
//! The catalog is operator-owned: a fetch names a catalog key, a listed URL,
//! or another page on a host the catalog already names - an absent catalog
//! entry never means an absent source. Redirects are followed only inside the
//! same authority: https, same host, no credentials, no query - so a
//! documentation page cannot bounce the gate into an arbitrary origin.
//! Self-located URLs carry no query or fragment, stay on a catalog host, and
//! connect only to globally routable addresses pinned by the resolver, keeping
//! the tool off local and private infrastructure. Ported from Money Saver's
//! `document` verb; the page extraction is byte-parity with its PageText,
//! pinned by the goldens.

use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
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
    fragment: Option<&'a str>,
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
    let fragment = query_and_fragment
        .split_once('#')
        .map(|(_, fragment)| fragment);
    Some(Split {
        scheme,
        authority,
        path: if path.is_empty() { "/" } else { path },
        query,
        fragment,
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
    // Unit tests drive a loopback HTTP fixture; a release build only ever
    // follows an https redirect.
    (target.scheme == "https" || (cfg!(test) && from.scheme == "http" && target.scheme == "http"))
        && target.authority == from.authority
        && !target.authority.contains('@')
        && target.query.is_none()
}

/// Whether an operator catalog entry may be fetched at all. Catalog URLs are
/// fetched as official evidence, so a release build accepts only https and
/// refuses URL credentials (which a proxy or a plaintext request could
/// expose). The loopback HTTP listener used by the unit tests is the one
/// deliberate exception.
fn catalog_source(url: &str) -> bool {
    let Some(parts) = split(url) else {
        return false;
    };
    if parts.authority.is_empty()
        || parts.authority.contains('@')
        || url.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return false;
    }
    parts.scheme == "https"
        || (cfg!(test) && parts.scheme == "http" && loopback_authority(parts.authority))
}

fn loopback_authority(authority: &str) -> bool {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').is_some_and(|(host, _)| host == "::1");
    }
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);
    host == "127.0.0.1" || host == "localhost"
}

/// A self-located URL's lexical requirements: https, no credentials, no
/// data-bearing query or fragment, a default TLS port, a real hostname
/// (never an IP literal), no local or single-label names, and a host the
/// operator's catalog already names. The address-space check happens at
/// fetch time through the pinned resolver in `fetch_direct`.
fn direct_url(name: &str, catalog_hosts: &HashSet<String>) -> Option<String> {
    let parts = split(name)?;
    if parts.scheme != "https"
        || parts.authority.is_empty()
        || parts.authority.contains('@')
        || parts.authority.starts_with('[')
        || parts.authority.contains(':')
        || parts.query.is_some()
        || parts.fragment.is_some()
        || name.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return None;
    }
    let host = parts.authority;
    if host.is_empty() || !host.contains('.') || host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let lowered = host.to_ascii_lowercase();
    const LOCAL_SUFFIXES: [&str; 5] = [".local", ".lan", ".internal", ".corp", ".localhost"];
    if lowered == "localhost"
        || LOCAL_SUFFIXES
            .iter()
            .any(|suffix| lowered.ends_with(suffix))
        || !catalog_hosts.contains(&lowered)
    {
        return None;
    }
    Some(name.to_string())
}

/// The deterministic cache key a self-located URL fetches under: stable
/// across a resumed run and safe as a filename.
fn direct_key(url: &str) -> String {
    format!("web-{}", &crate::util::sha256(url)[..16])
}

/// An address the egress guard lets an official page be fetched from: the
/// global-unicast space, minus loopback, private, link-local, shared,
/// documentation, benchmark, reserved, transition and multicast ranges.
fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(addr) => {
            let o = addr.octets();
            !(o[0] == 0
                || o[0] == 10
                || o[0] == 127
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 192 && o[1] == 31 && o[2] == 196)
                || (o[0] == 192 && o[1] == 52 && o[2] == 193)
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 192 && o[1] == 175 && o[2] == 48)
                || (o[0] == 198 && (o[1] & 0xFE) == 18)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                || o[0] >= 224)
        }
        std::net::IpAddr::V6(addr) => {
            if let Some(mapped) = addr.to_ipv4_mapped() {
                return is_public_ip(std::net::IpAddr::V4(mapped));
            }
            let segments = addr.segments();
            let head = segments[0];
            // Only 2000::/3 is globally routable unicast.
            if (head & 0xE000) != 0x2000 {
                return false;
            }
            // Teredo, benchmark, ORCHID, documentation and 6to4 ranges are
            // transition or documentation space, never a documentation host.
            if head == 0x2001
                && (segments[1] == 0
                    || (segments[1] == 0x0002 && segments[2] == 0)
                    || (segments[1] & 0xFFF0) == 0x0010
                    || (segments[1] & 0xFFF0) == 0x0020
                    || segments[1] == 0x0DB8)
            {
                return false;
            }
            if head == 0x2002 {
                return false;
            }
            if head == 0x3FFF && (segments[1] & 0xF000) == 0 {
                return false;
            }
            // 5f00::/16 is the SRv6 SID space, not a public web host.
            head != 0x5F00
        }
    }
}

/// A resolver ureq hands straight to the transport: it resolves a name once,
/// refuses the whole answer if any address is outside global unicast space,
/// and returns the validated addresses. The transport then connects to one of
/// these addresses — it never performs a second lookup — so a name cannot pass
/// the check on a public address and be connected to a private one.
#[derive(Debug)]
struct PublicResolver;

impl ureq::unversioned::resolver::Resolver for PublicResolver {
    fn resolve(
        &self,
        uri: &http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let resolved = ureq::unversioned::resolver::DefaultResolver::default()
            .resolve(uri, config, timeout)?;
        if resolved.iter().any(|address| !is_public_ip(address.ip())) {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(resolved)
    }
}

/// The ordinary catalog fetcher's agent. Redirects stay in this module so
/// each hop is policy-checked before it is requested. A catalog host is held
/// to the same egress policy as a self-located URL: no environment proxy and
/// only pinned global-unicast addresses. The loopback fixture used by the
/// unit tests is the sole exception.
fn catalog_agent() -> ureq::Agent {
    if cfg!(test) {
        ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .build(),
        )
    } else {
        public_agent()
    }
}

/// The self-located fetcher's agent: no environment-provided proxy (a proxy
/// would resolve and reach the destination on our behalf) and the pinned
/// public-address resolver above.
fn public_agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .proxy(None)
        .build();
    ureq::Agent::with_parts(
        config,
        ureq::unversioned::transport::DefaultConnector::default(),
        PublicResolver,
    )
}

/// Fetch one self-located official page. The catalog-host allowlist was
/// checked in `direct_url`; the transport resolves only public addresses and
/// honours the same redirect constraints as a catalog page.
fn fetch_direct(url: &str) -> Result<String, String> {
    fetch_with(url, &public_agent())
}

/// Fetch one document, following policy-checked redirects. Returns the body
/// and whether it was HTML. A repeated URL is a redirect loop, not a fixed
/// hop budget: a long but acyclic chain still reaches its page.
fn fetch(url: &str) -> Result<String, String> {
    fetch_with(url, &catalog_agent())
}

fn fetch_with(url: &str, agent: &ureq::Agent) -> Result<String, String> {
    if !catalog_source(url) {
        return Err(
            "Official documentation must be fetched over https without credentials".to_string(),
        );
    }
    let mut url = url.split('#').next().unwrap_or(url).to_string();
    let mut visited = HashSet::new();
    visited.insert(url.clone());
    loop {
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
            let target = target.split('#').next().unwrap_or(&target).to_string();
            if !visited.insert(target.clone()) {
                return Err("Official documentation redirects in a loop".to_string());
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
}

pub struct Doc {
    pub url: String,
    pub accessed: String,
    pub content: String,
}

/// The catalog, the self-located URLs accepted this review and the fetched
/// cache. The cache doubles as the verdict's evidence trail: what was never
/// fetched cannot be cited.
pub struct Documents {
    catalog: Map<String, Value>,
    /// The hosts the operator's catalog names. Self-located URLs are limited
    /// to these hosts; the catalog stays the curated source registry even
    /// when a page is not listed.
    catalog_hosts: HashSet<String>,
    /// Self-located URL keys (`web-*`) to their URL - resolve-derived or
    /// restored from a persisted run.
    direct: HashMap<String, String>,
    cache: HashMap<String, Doc>,
}

impl Documents {
    /// Load the operator's catalog. Every entry is validated before anything
    /// can be fetched: an http or credential-bearing source would let a
    /// network intermediary dress its own page up as official evidence.
    pub fn new(catalog: Map<String, Value>) -> Result<Documents, String> {
        for (key, value) in &catalog {
            let Some(url) = value.as_str() else {
                return Err(format!(
                    "documents.json: catalog entry '{key}' is not a URL string"
                ));
            };
            if !catalog_source(url) {
                return Err(format!(
                    "documents.json: catalog entry '{key}' is not an https URL without credentials"
                ));
            }
        }
        let catalog_hosts = catalog
            .values()
            .filter_map(Value::as_str)
            .filter_map(split)
            .filter(|parts| parts.scheme == "https")
            .map(|parts| {
                parts
                    .authority
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
            })
            .filter(|host| !host.is_empty())
            .collect();
        Ok(Documents {
            catalog,
            catalog_hosts,
            direct: HashMap::new(),
            cache: HashMap::new(),
        })
    }

    /// The URLs of every fetched document - the set submit validation cites.
    pub fn fetched(&self) -> std::collections::HashSet<String> {
        self.cache.values().map(|doc| doc.url.clone()).collect()
    }

    /// Resolve a catalog key, a listed URL or a self-located official https
    /// URL to the key the fetch and the page cache share.
    pub fn resolve(&mut self, name: &str) -> Result<String, String> {
        if name.is_empty() {
            return Err("operation \"document\" requires a \"name\" argument".to_string());
        }
        if self.catalog.contains_key(name) || self.direct.contains_key(name) {
            return Ok(name.to_string());
        }
        if let Some(key) = self
            .catalog
            .iter()
            .find(|(_, url)| url.as_str() == Some(name))
            .map(|(key, _)| key.clone())
        {
            return Ok(key);
        }
        if let Some(url) = direct_url(name, &self.catalog_hosts) {
            let key = direct_key(&url);
            self.direct.insert(key.clone(), url);
            return Ok(key);
        }
        Err(format!(
            "Choose an exact catalog key, a listed URL, or an https URL on a catalog host, \
             with no query or fragment. Keys: {}",
            self.catalog.keys().cloned().collect::<Vec<_>>().join(", ")
        ))
    }

    pub fn is_cached(&self, key: &str) -> bool {
        self.cache.contains_key(key)
    }

    /// Iterate the fetched documents (for the receipt's source list).
    pub fn cached_docs(&self) -> impl Iterator<Item = &Doc> {
        self.cache.values()
    }

    /// The full document, for persistence - never the paged reply.
    pub fn cached(&self, key: &str) -> Option<&Doc> {
        self.cache.get(key)
    }

    /// A persisted document rejoins the cache - a resumed run does not
    /// refetch. A self-located `web-*` key rejoins the direct map so the same
    /// URL resolves without another validation pass.
    pub fn restore(&mut self, key: String, doc: Doc) {
        if !self.catalog.contains_key(&key)
            && direct_url(&doc.url, &self.catalog_hosts).is_some_and(|url| direct_key(&url) == key)
        {
            self.direct.insert(key.clone(), doc.url.clone());
        }
        self.cache.insert(key, doc);
    }

    /// A persisted document may rejoin when its key is in the catalog or its
    /// stored URL re-derives the same self-located key.
    pub fn restorable(&self, key: &str, url: &str) -> bool {
        self.catalog.contains_key(key)
            || direct_url(url, &self.catalog_hosts).is_some_and(|url| direct_key(&url) == key)
    }

    /// One document page: fetch on first use, then character-paged. Catalog
    /// keys fetch their listed URL; self-located keys fetch through the
    /// public-egress guard.
    pub fn get(&mut self, name: &str, offset: i64) -> Result<Value, String> {
        let key = self.resolve(name)?;
        if !self.cache.contains_key(&key) {
            let url = self
                .catalog
                .get(&key)
                .and_then(Value::as_str)
                .or_else(|| self.direct.get(&key).map(String::as_str))
                .ok_or("The catalog maps keys to URLs")?
                .to_string();
            let content = if self.direct.contains_key(&key) {
                fetch_direct(&url)?
            } else {
                fetch(&url)?
            };
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
    use super::{Documents, direct_url, is_public_ip, page_text, redirect_allowed, resolve};
    use serde_json::{Map, Value, json};
    use std::collections::HashSet;
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
        let mut docs = Documents::new(catalog).unwrap();
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
        let mut docs = Documents::new(catalog).unwrap();
        assert!(
            docs.get("loop", 0)
                .unwrap_err()
                .contains("redirects in a loop")
        );
        assert!(
            docs.get("plain", 0)
                .unwrap_err()
                .contains("outside its authority")
        );
        assert!(docs.get("gone", 0).unwrap_err().contains("HTTP 404"));
    }

    fn catalog_for(url: &str) -> Map<String, Value> {
        let mut catalog = Map::new();
        catalog.insert("seed".into(), json!(url));
        catalog
    }

    #[test]
    fn self_located_urls_resolve_to_web_keys() {
        let mut docs = Documents::new(catalog_for("https://docs.example.com/seed")).unwrap();
        let url = "https://docs.example.com/pricing";
        let key = docs.resolve(url).unwrap();
        assert!(key.starts_with("web-"), "{key}");
        // The same URL resolves to the same cached key - one fetch per page.
        assert_eq!(docs.resolve(url).unwrap(), key);
        assert_eq!(docs.resolve(&key).unwrap(), key);
        // A persisted self-located document rejoins under its derived key.
        let mut restored = Documents::new(catalog_for("https://docs.example.com/seed")).unwrap();
        assert!(restored.restorable(&key, url));
        assert!(!restored.restorable(&key, "https://other.example.com/"));
        assert!(!restored.restorable("web-anything", "not a url"));
        restored.restore(
            key.clone(),
            super::Doc {
                url: url.to_string(),
                accessed: "2026-01-01".to_string(),
                content: "cached".to_string(),
            },
        );
        assert_eq!(restored.resolve(url).unwrap(), key);
    }

    #[test]
    fn self_located_url_lexical_guards() {
        let hosts: HashSet<String> = ["docs.example.com".to_string()].into_iter().collect();
        for url in [
            "http://docs.example.com/",           // not https
            "https://user@docs.example.com/",     // credentials
            "https://10.0.0.1/private",           // IP literal
            "https://[fd00::1]/",                 // IPv6 literal
            "https://localhost/",                 // local name
            "https://printer.internal/docs",      // local suffix
            "https://singlelabel/docs",           // no public shape
            "https://docs.example.com/?q=x",      // data-bearing query
            "https://docs.example.com/#part",     // fragment
            "https://docs.example.com:8443/x",    // non-default port
            "https://docs.github.com/en/actions", // host not in the catalog
            "not a url",
        ] {
            assert_eq!(direct_url(url, &hosts), None, "{url}");
        }
        assert_eq!(
            direct_url("https://docs.example.com/en/actions", &hosts).as_deref(),
            Some("https://docs.example.com/en/actions")
        );
        // The operator's catalog is the source registry: a host the catalog
        // names is admissible, a host it does not name never is.
        assert_eq!(
            direct_url("https://docs.github.com/en/actions", &hosts),
            None,
            "an absent catalog host is not an implicit approval"
        );
        let mut catalog = Map::new();
        catalog.insert(
            "billing".into(),
            json!("https://docs.github.com/en/billing"),
        );
        let mut docs = Documents::new(catalog).unwrap();
        assert!(docs.resolve("https://docs.github.com/en/actions").is_ok());
        assert!(
            docs.resolve("https://unlisted.example.com/actions")
                .unwrap_err()
                .contains("catalog host")
        );
    }

    #[test]
    fn catalog_sources_must_be_https_without_credentials() {
        for url in [
            "http://docs.example.com/page",
            "https://user:secret@docs.example.com/page",
            "ftp://docs.example.com/page",
            "not a url",
        ] {
            let mut catalog = Map::new();
            catalog.insert("seed".into(), json!(url));
            let error = match Documents::new(catalog) {
                Ok(_) => panic!("{url} must be refused before anything is fetched"),
                Err(error) => error,
            };
            assert!(error.contains("seed"), "{url}: {error}");
        }
        // The unit-test loopback listener is the one deliberate http
        // exception; a public http source is never admitted.
        let mut local = Map::new();
        local.insert("fixture".into(), json!("http://127.0.0.1:1/page"));
        assert!(Documents::new(local).is_ok());
    }

    #[test]
    fn public_address_policy_covers_special_use_ranges() {
        for address in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(is_public_ip(address.parse().unwrap()), "{address}");
        }
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "100::1",
            "2001::1",
            "2001:2::1",
            "2001:10::1",
            "2001:20::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn a_long_acyclic_redirect_chain_settles() {
        // Thirteen hops is deliberately longer than the old ten-request
        // budget; it must reach the page rather than be truncated.
        let mut routes: Vec<(&'static str, &'static str)> = (0..13)
            .map(|index| {
                let path: &'static str = Box::leak(format!("/hop{index}").into_boxed_str());
                let body: &'static str =
                    Box::leak(format!("301\n/hop{}", index + 1).into_boxed_str());
                (path, body)
            })
            .collect();
        routes.push(("/hop13", "text/plain\narrived"));
        let server = serve(routes);
        let mut catalog = Map::new();
        catalog.insert("chain".into(), json!(format!("{}/hop0", server.url)));
        let mut docs = Documents::new(catalog).unwrap();
        let page = docs.get("chain", 0).unwrap();
        assert_eq!(page["content"], "arrived");
        assert_eq!(server.hits.load(Ordering::Relaxed), 14);
    }
}
