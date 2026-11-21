use crate::config::proxy::{ProxyParseError, is_supported_uri, proxy_display_name, proxy_from_uri};
use crate::net::default_user_agent;
use base64::{Engine, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::time::Duration;
use thiserror::Error;

const MAX_SUBSCRIPTION_BYTES: u64 = 10 * 1024 * 1024;
const SUBSCRIPTION_TIMEOUT: Duration = Duration::from_secs(25);

/// The subscription the application ships with, seeded on first run so the app
/// is usable out of the box. Users can add their own on top of it.
///
/// The address is not kept in the source tree: it is baked in at build time from
/// `VRG_DEFAULT_SUBSCRIPTION_URL`, which release builds take from the repository
/// secret of the same name. A build made without that variable simply ships no
/// subscription, and the person adds their own address in the settings.
pub const DEFAULT_SUBSCRIPTION_URL: &str = match option_env!("VRG_DEFAULT_SUBSCRIPTION_URL") {
    Some(url) => url,
    None => "",
};

/// Describes the subscription itself, as opposed to the servers in it.
///
/// Providers publish this alongside the node list in response headers: a
/// display title, a free-text announcement, where to get help, and the traffic
/// counters. The UI shows these instead of raw node data.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub announce: Option<String>,
    #[serde(default)]
    pub support_url: Option<String>,
    #[serde(default)]
    pub web_page_url: Option<String>,
    #[serde(default)]
    pub upload_bytes: Option<u64>,
    #[serde(default)]
    pub download_bytes: Option<u64>,
    /// Traffic allowance. Zero from the provider means "unmetered" and is
    /// normalized to `None` here so the UI does not render a 0-byte quota.
    #[serde(default)]
    pub total_bytes: Option<u64>,
    /// Unix seconds. Zero from the provider means "never" and becomes `None`.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// A subscription body together with whatever the provider said about it.
#[derive(Debug, Clone)]
pub struct FetchedSubscription {
    pub document: SubscriptionDocument,
    pub info: SubscriptionInfo,
}

#[derive(Clone)]
pub struct SubscriptionClient {
    client: reqwest::Client,
}

impl SubscriptionClient {
    pub fn new(user_agent_override: Option<String>) -> Result<Self, SubscriptionError> {
        let user_agent = user_agent_override.unwrap_or_else(default_user_agent);
        let client = reqwest::Client::builder()
            .user_agent(user_agent)
            .https_only(true)
            .timeout(SUBSCRIPTION_TIMEOUT)
            .build()?;
        Ok(Self { client })
    }

    pub async fn fetch(&self, url: &str) -> Result<FetchedSubscription, SubscriptionError> {
        let mut response = self.client.get(url).send().await?.error_for_status()?;
        // `Content-Length` is only a hint: it is absent under chunked encoding and
        // a hostile endpoint can simply understate it. Check it anyway to fail
        // fast on the honest case.
        if response
            .content_length()
            .is_some_and(|length| length > MAX_SUBSCRIPTION_BYTES)
        {
            return Err(SubscriptionError::ResponseTooLarge(MAX_SUBSCRIPTION_BYTES));
        }

        // Read the provider's description before consuming the body.
        let info = subscription_info_from_headers(response.headers());

        // Stream the body so the cap is a real limit rather than something checked
        // once the whole response is already resident in memory.
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() as u64 + chunk.len() as u64 > MAX_SUBSCRIPTION_BYTES {
                return Err(SubscriptionError::ResponseTooLarge(MAX_SUBSCRIPTION_BYTES));
            }
            bytes.extend_from_slice(&chunk);
        }

        let body = std::str::from_utf8(&bytes).map_err(|_| SubscriptionError::InvalidUtf8)?;
        Ok(FetchedSubscription {
            document: parse_subscription_response(body)?,
            info,
        })
    }
}

/// Read the de-facto subscription headers Clash-style providers send.
///
/// `profile-title` and `announce` are commonly `base64:`-prefixed so they can
/// carry non-ASCII text through a header.
fn subscription_info_from_headers(headers: &reqwest::header::HeaderMap) -> SubscriptionInfo {
    let text = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(decode_header_text)
            .filter(|value| !value.is_empty())
    };

    let mut info = SubscriptionInfo {
        title: text("profile-title"),
        announce: text("announce"),
        support_url: text("support-url"),
        web_page_url: text("profile-web-page-url"),
        ..SubscriptionInfo::default()
    };

    if let Some(userinfo) = headers
        .get("subscription-userinfo")
        .and_then(|value| value.to_str().ok())
    {
        // "upload=0; download=123; total=0; expire=0"
        for field in userinfo.split(';') {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            let Ok(number) = value.trim().parse::<u64>() else {
                continue;
            };
            match key.trim() {
                "upload" => info.upload_bytes = Some(number),
                "download" => info.download_bytes = Some(number),
                // Zero means unlimited/never for both of these.
                "total" => info.total_bytes = (number > 0).then_some(number),
                "expire" => info.expires_at = (number > 0).then_some(number),
                _ => {}
            }
        }
    }

    info
}

/// Decode a `base64:`-prefixed header value, falling back to the raw text.
fn decode_header_text(value: &str) -> String {
    let trimmed = value.trim();
    let Some(encoded) = trimmed.strip_prefix("base64:") else {
        return trimmed.to_owned();
    };
    decode_base64_subscription(encoded.trim())
        .map(|decoded| decoded.trim().to_owned())
        .unwrap_or_else(|| trimmed.to_owned())
}

/// Parse a subscription body into a set of Mihomo proxy nodes.
///
/// Three input shapes are supported, in order:
/// 1. A Clash/Mihomo YAML document with a top-level `proxies:` list — used
///    directly (this is the most faithful path for Clash subscriptions).
/// 2. A JSON document holding an array of nodes (or a `{proxies|servers|...}`
///    wrapper) — each entry is treated as a proxy map.
/// 3. A plain or base64-encoded list of proxy URIs (`vless://`, `vmess://`,
///    `trojan://`, `ss://`, `hysteria2://`), one per line.
pub fn parse_subscription_response(body: &str) -> Result<SubscriptionDocument, SubscriptionError> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err(SubscriptionError::NoUsableNode);
    }

    // A single proxy URI pasted directly.
    if is_supported_uri(trimmed) && !trimmed.contains('\n') {
        let proxy = proxy_from_uri(trimmed)?;
        return Ok(SubscriptionDocument::Proxies(vec![proxy]));
    }

    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let json: Value = serde_json::from_str(trimmed)?;
        let proxies = proxies_from_json(json);
        if proxies.is_empty() {
            return Err(SubscriptionError::NoUsableNode);
        }
        return Ok(SubscriptionDocument::Proxies(proxies));
    }

    // A Clash/Mihomo YAML document carrying a `proxies:` list.
    if let Ok(Value::Object(map)) = serde_yaml::from_str::<Value>(trimmed)
        && let Some(Value::Array(proxies)) = map.get("proxies")
    {
        let proxies: Vec<Value> = proxies
            .iter()
            .filter(|proxy| proxy.is_object())
            .cloned()
            .collect();
        if !proxies.is_empty() {
            return Ok(SubscriptionDocument::Proxies(proxies));
        }
    }

    // Otherwise treat the body (optionally base64-encoded) as a URI list.
    let decoded = decode_base64_subscription(trimmed);
    let source = decoded.as_deref().unwrap_or(trimmed);

    let proxies = source
        .lines()
        .flat_map(|line| line.split_whitespace())
        .map(str::trim)
        .filter(|token| is_supported_uri(token))
        .map(proxy_from_uri)
        .collect::<Result<Vec<_>, _>>()?;

    if proxies.is_empty() {
        Err(SubscriptionError::NoUsableNode)
    } else {
        Ok(SubscriptionDocument::Proxies(proxies))
    }
}

/// Extract proxy nodes from a JSON document: either an array of nodes or an
/// object wrapping them under a well-known key.
fn proxies_from_json(json: Value) -> Vec<Value> {
    let entries = match json {
        Value::Array(entries) => entries,
        Value::Object(mut object) => {
            let mut found = None;
            for key in ["proxies", "servers", "nodes", "outbounds"] {
                if let Some(Value::Array(entries)) = object.remove(key) {
                    found = Some(entries);
                    break;
                }
            }
            found.unwrap_or_else(|| vec![Value::Object(object)])
        }
        _ => return Vec::new(),
    };

    entries.into_iter().filter(Value::is_object).collect()
}

fn decode_base64_subscription(value: &str) -> Option<String> {
    [
        general_purpose::STANDARD,
        general_purpose::STANDARD_NO_PAD,
        general_purpose::URL_SAFE,
        general_purpose::URL_SAFE_NO_PAD,
    ]
    .into_iter()
    .find_map(|engine| engine.decode(value).ok())
    .and_then(|bytes| String::from_utf8(bytes).ok())
}

#[derive(Debug, Clone)]
pub enum SubscriptionDocument {
    Proxies(Vec<Value>),
}

impl SubscriptionDocument {
    pub fn profile_names(&self) -> Vec<String> {
        match self {
            Self::Proxies(proxies) => proxies.iter().map(mihomo_proxy_name).collect(),
        }
    }
}

pub fn stored_profiles_from_document(
    document: SubscriptionDocument,
    source_url: Option<&str>,
) -> Vec<StoredVpnProfile> {
    match document {
        SubscriptionDocument::Proxies(proxies) => proxies
            .into_iter()
            .map(|proxy| {
                let mut profile = StoredVpnProfile::from_proxy(proxy);
                profile.source_url = source_url.map(str::to_owned);
                profile
            })
            .collect(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredVpnProfile {
    pub id: String,
    pub name: String,
    /// A Mihomo (Clash.Meta) proxy map.
    pub proxy: Value,
    /// The subscription URL this profile was imported from, when it came from a
    /// remote endpoint. Used to refresh the proxy on start. `None` for profiles
    /// pasted as a literal `vless://` URI or JSON, which cannot be re-fetched.
    #[serde(default)]
    pub source_url: Option<String>,
}

impl StoredVpnProfile {
    /// A stable identifier for a proxy, derived from the endpoint it describes.
    ///
    /// The identifier used to include the node's position in the subscription.
    /// Providers reorder freely, and the old slug collapsed every all-Cyrillic
    /// name to the same string, so the index was frequently the only thing
    /// telling two profiles apart: a reordered list re-pointed the user's
    /// selection at a different server, and a replaced list could produce
    /// exactly the previous set of identifiers and be skipped as "already
    /// imported". Hashing the connection details instead means the identity
    /// follows the server.
    pub fn identifier(proxy: &Value) -> String {
        let kind = proxy.get("type").and_then(Value::as_str).unwrap_or("proxy");
        let field = |key: &str| match proxy.get(key) {
            Some(Value::String(text)) => text.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        };
        // Everything that distinguishes one endpoint from another. `name` is
        // deliberately excluded: providers relabel nodes without moving them.
        let parts = [
            kind.to_owned(),
            field("server"),
            field("port"),
            field("uuid"),
            field("password"),
            field("cipher"),
            field("network"),
            field("servername"),
        ];
        format!("{kind}-{:016x}", stable_hash(&parts))
    }

    pub fn from_proxy(proxy: Value) -> Self {
        let name = mihomo_proxy_name(&proxy);
        let id = Self::identifier(&proxy);
        Self {
            id,
            name,
            proxy,
            source_url: None,
        }
    }
}

/// FNV-1a over the given parts, with a separator so `["ab","c"]` and `["a","bc"]`
/// do not collide.
///
/// Deliberately not `DefaultHasher`: this value is written to settings.json, and
/// the standard hasher's algorithm is explicitly allowed to change between Rust
/// releases, which would silently invalidate every stored identifier.
fn stable_hash(parts: &[String]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// A display name for a Mihomo proxy map, preferring an existing `name` field,
/// then the parser's internal `__remark`, then the server host.
fn mihomo_proxy_name(proxy: &Value) -> String {
    for key in ["name", "__remark"] {
        if let Some(name) = proxy.get(key).and_then(Value::as_str) {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
        }
    }
    proxy_display_name(proxy)
}

/// Strip the parser's internal bookkeeping keys (prefixed with `__`) from a
/// proxy map so only Mihomo-recognized fields remain. Callers use this before
/// handing a stored proxy to the config builder.
pub fn sanitize_proxy(proxy: &Value) -> Value {
    match proxy {
        Value::Object(map) => {
            let cleaned: Map<String, Value> = map
                .iter()
                .filter(|(key, _)| !key.starts_with("__"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            Value::Object(cleaned)
        }
        other => other.clone(),
    }
}

#[derive(Debug, Error)]
pub enum SubscriptionError {
    #[error("failed to build HTTP client: {0}")]
    Client(#[from] reqwest::Error),
    #[error("invalid remote JSON configuration: {0}")]
    Json(#[from] serde_json::Error),
    #[error("subscription response exceeded {0} bytes")]
    ResponseTooLarge(u64),
    #[error("subscription response was not valid UTF-8")]
    InvalidUtf8,
    #[error("invalid proxy link: {0}")]
    Proxy(#[from] ProxyParseError),
    #[error("subscription response did not contain a usable proxy node or configuration")]
    NoUsableNode,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_live_base64_vless_subscription_shape() {
        let body = "dmxlc3M6Ly8wMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDBAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZSZ0eXBlPXRjcCZzZWN1cml0eT1yZWFsaXR5JnNuaT1leGFtcGxlLmNvbSZmcD1maXJlZm94JnBiaz1BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBJnNpZD0wMDAwMDAwMDAwMDAwMDAwIyVGMCU5RiU4NyVBQiVGMCU5RiU4NyVBRUZpbmxhbmQlMjAtJTIwVENQ";
        let parsed = parse_subscription_response(body).expect("subscription should parse");
        let SubscriptionDocument::Proxies(proxies) = parsed;

        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0]["type"], json!("vless"));
        assert_eq!(proxies[0]["server"], json!("example.com"));
        assert_eq!(proxies[0]["port"], json!(443));
        assert_eq!(mihomo_proxy_name(&proxies[0]), "🇫🇮Finland - TCP");
    }

    #[test]
    fn parses_multiple_plain_uris_as_proxies() {
        let body = "vless://00000000-0000-0000-0000-000000000000@example.com:443?encryption=none&type=tcp#One\nvless://00000000-0000-0000-0000-000000000000@example.org:8443?encryption=none&type=ws#Two";
        let parsed = parse_subscription_response(body).expect("subscription should parse");
        let SubscriptionDocument::Proxies(proxies) = parsed;

        assert_eq!(proxies.len(), 2);
        assert_eq!(mihomo_proxy_name(&proxies[0]), "One");
        assert_eq!(mihomo_proxy_name(&proxies[1]), "Two");
    }

    #[test]
    fn parses_clash_yaml_proxies_passthrough() {
        let body = r#"
proxies:
  - name: "Node A"
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
"#;
        let parsed = parse_subscription_response(body).expect("yaml should parse");
        let SubscriptionDocument::Proxies(proxies) = parsed;
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0]["name"], json!("Node A"));
        assert_eq!(proxies[0]["type"], json!("vless"));
    }

    #[test]
    fn reads_the_provider_description_from_headers() {
        // Header shapes providers send; the values are placeholders.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "profile-title",
            "base64:0J/RgNC+0LLQsNC50LTQtdGAIOKchQ==".parse().unwrap(),
        );
        headers.insert(
            "support-url",
            "https://example.com/support".parse().unwrap(),
        );
        headers.insert(
            "subscription-userinfo",
            "upload=0; download=1234567890; total=0; expire=0"
                .parse()
                .unwrap(),
        );

        let info = subscription_info_from_headers(&headers);
        assert_eq!(info.title.as_deref(), Some("Провайдер ✅"));
        assert_eq!(
            info.support_url.as_deref(),
            Some("https://example.com/support")
        );
        assert_eq!(info.download_bytes, Some(1_234_567_890));
        // Zero means unlimited / never, not "no traffic left" and not "expired".
        assert_eq!(info.total_bytes, None);
        assert_eq!(info.expires_at, None);
    }

    #[test]
    fn keeps_plain_header_text_as_is() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("profile-title", "My Provider".parse().unwrap());
        let info = subscription_info_from_headers(&headers);
        assert_eq!(info.title.as_deref(), Some("My Provider"));
    }

    /// The bug this replaced: identifiers carried the node's index, and every
    /// all-Cyrillic name slugged to the same string, so reordering a subscription
    /// silently moved the user's selection to a different server.
    #[test]
    fn profile_identity_survives_reordering_and_renaming() {
        let finland = json!({
            "name": "Финляндия — TCP", "type": "vless",
            "server": "fi.example.com", "port": 443,
            "uuid": "00000000-0000-0000-0000-000000000000"
        });
        let sweden = json!({
            "name": "Швеция", "type": "vless",
            "server": "se.example.com", "port": 443,
            "uuid": "00000000-0000-0000-0000-000000000000"
        });

        // Two different endpoints must not collide, even though both names are
        // entirely non-Latin.
        assert_ne!(
            StoredVpnProfile::identifier(&finland),
            StoredVpnProfile::identifier(&sweden)
        );

        // The same endpoint keeps its identifier wherever it appears in the list.
        let first = stored_profiles_from_document(
            SubscriptionDocument::Proxies(vec![finland.clone(), sweden.clone()]),
            Some("https://example.com/sub"),
        );
        let reordered = stored_profiles_from_document(
            SubscriptionDocument::Proxies(vec![sweden, finland]),
            Some("https://example.com/sub"),
        );
        assert_eq!(first[0].id, reordered[1].id);
        assert_eq!(first[1].id, reordered[0].id);
    }

    /// Providers relabel nodes without moving them, so the display name must not
    /// take part in identity — otherwise a rename looks like a brand-new server.
    #[test]
    fn renaming_a_node_does_not_change_its_identity() {
        let before = json!({
            "name": "Финляндия", "type": "vless",
            "server": "fi.example.com", "port": 443, "uuid": "abc"
        });
        let after = json!({
            "name": "Finland (new)", "type": "vless",
            "server": "fi.example.com", "port": 443, "uuid": "abc"
        });
        assert_eq!(
            StoredVpnProfile::identifier(&before),
            StoredVpnProfile::identifier(&after)
        );
    }

    /// A moved endpoint is a different server and must get a different identifier.
    #[test]
    fn moving_a_node_to_another_host_changes_its_identity() {
        let before = json!({ "type": "vless", "server": "fi.example.com", "port": 443 });
        let after = json!({ "type": "vless", "server": "de.example.com", "port": 443 });
        assert_ne!(
            StoredVpnProfile::identifier(&before),
            StoredVpnProfile::identifier(&after)
        );
    }

    #[test]
    fn sanitize_strips_internal_keys() {
        let proxy = json!({ "type": "vless", "server": "x", "__remark": "label" });
        let cleaned = sanitize_proxy(&proxy);
        assert!(cleaned.get("__remark").is_none());
        assert_eq!(cleaned["type"], json!("vless"));
    }
}
