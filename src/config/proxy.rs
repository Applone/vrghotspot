//! Parse proxy-node subscription URIs into Mihomo (Clash.Meta) proxy maps.
//!
//! Each supported scheme is converted into a `serde_json::Value` object whose
//! keys match Mihomo's `proxies:` schema (`type`, `server`, `port`, ...). JSON
//! is a subset of YAML, so the map serializes directly into the generated
//! Mihomo config. Supported schemes: `vless`, `vmess`, `trojan`, `ss`
//! (shadowsocks), and `hysteria2`/`hy2`.

use base64::{Engine, engine::general_purpose};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use thiserror::Error;
use url::Url;

/// Parse a single proxy URI into a Mihomo proxy map.
pub fn proxy_from_uri(input: &str) -> Result<Value, ProxyParseError> {
    let input = input.trim();
    let scheme = input
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .ok_or(ProxyParseError::MissingScheme)?;

    match scheme.as_str() {
        "vless" => parse_vless(input),
        "vmess" => parse_vmess(input),
        "trojan" => parse_trojan(input),
        "ss" => parse_shadowsocks(input),
        "hysteria2" | "hy2" => parse_hysteria2(input),
        other => Err(ProxyParseError::UnsupportedScheme(other.to_owned())),
    }
}

/// The subscription schemes this parser understands, used to filter tokens out
/// of a plain (or base64) node list.
pub fn is_supported_uri(token: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
        "hysteria2://",
        "hy2://",
    ];
    PREFIXES.iter().any(|prefix| token.starts_with(prefix))
}

/// A human-readable name for a parsed proxy, preferring the URI fragment
/// (percent-decoded) and falling back to the server host.
pub fn proxy_display_name(proxy: &Value) -> String {
    proxy
        .get("__remark")
        .and_then(Value::as_str)
        .filter(|remark| !remark.trim().is_empty())
        .or_else(|| proxy.get("server").and_then(Value::as_str))
        .unwrap_or("proxy")
        .trim()
        .to_owned()
}

fn parse_vless(input: &str) -> Result<Value, ProxyParseError> {
    let url = Url::parse(input).map_err(ProxyParseError::Url)?;
    let uuid = url.username();
    if uuid.is_empty() {
        return Err(ProxyParseError::MissingField("uuid"));
    }
    let (server, port) = host_port(&url)?;
    let params: BTreeMap<String, String> = url.query_pairs().into_owned().collect();

    let network = param(&params, "type").unwrap_or("tcp");
    let security = param(&params, "security").unwrap_or("none");

    let mut proxy = Map::new();
    proxy.insert("type".into(), json!("vless"));
    proxy.insert("server".into(), json!(server));
    proxy.insert("port".into(), json!(port));
    proxy.insert("uuid".into(), json!(uuid));
    proxy.insert("udp".into(), json!(true));
    proxy.insert("network".into(), json!(network));
    if let Some(flow) = param(&params, "flow").filter(|flow| !flow.is_empty()) {
        proxy.insert("flow".into(), json!(flow));
    }

    apply_tls_and_reality(&mut proxy, &params, security, &server);
    apply_transport(&mut proxy, &params, network);
    attach_remark(&mut proxy, &url);
    Ok(Value::Object(proxy))
}

fn parse_vmess(input: &str) -> Result<Value, ProxyParseError> {
    // VMess subscription links are `vmess://<base64 of a JSON blob>` (the
    // v2rayN format). Decode and translate the JSON fields.
    let encoded = input.trim_start_matches("vmess://").trim();
    let decoded = decode_base64(encoded).ok_or(ProxyParseError::InvalidBase64)?;
    let blob: Value =
        serde_json::from_str(&decoded).map_err(|_| ProxyParseError::MissingField("vmess json"))?;

    let server = str_field(&blob, &["add"]).ok_or(ProxyParseError::MissingField("server"))?;
    let port = port_field(&blob, &["port"]).ok_or(ProxyParseError::MissingField("port"))?;
    let uuid = str_field(&blob, &["id"]).ok_or(ProxyParseError::MissingField("uuid"))?;
    let network = str_field(&blob, &["net"]).unwrap_or("tcp");

    let mut proxy = Map::new();
    proxy.insert("type".into(), json!("vmess"));
    proxy.insert("server".into(), json!(server));
    proxy.insert("port".into(), json!(port));
    proxy.insert("uuid".into(), json!(uuid));
    proxy.insert(
        "alterId".into(),
        json!(port_field(&blob, &["aid"]).unwrap_or(0)),
    );
    proxy.insert(
        "cipher".into(),
        json!(str_field(&blob, &["scy"]).unwrap_or("auto")),
    );
    proxy.insert("udp".into(), json!(true));
    proxy.insert("network".into(), json!(network));

    let tls = str_field(&blob, &["tls"]).unwrap_or("");
    if tls == "tls" || tls == "reality" {
        proxy.insert("tls".into(), json!(true));
        if let Some(sni) = str_field(&blob, &["sni", "host"]) {
            proxy.insert("servername".into(), json!(sni));
        }
    }

    // ws/grpc transport carried in `host`/`path` fields.
    match network {
        "ws" => {
            let mut ws = Map::new();
            if let Some(path) = str_field(&blob, &["path"]) {
                ws.insert("path".into(), json!(path));
            }
            if let Some(host) = str_field(&blob, &["host"]) {
                ws.insert("headers".into(), json!({ "Host": host }));
            }
            if !ws.is_empty() {
                proxy.insert("ws-opts".into(), Value::Object(ws));
            }
        }
        "grpc" => {
            if let Some(path) = str_field(&blob, &["path"]) {
                proxy.insert("grpc-opts".into(), json!({ "grpc-service-name": path }));
            }
        }
        _ => {}
    }

    if let Some(name) = str_field(&blob, &["ps"]) {
        proxy.insert("__remark".into(), json!(name));
    }
    Ok(Value::Object(proxy))
}

fn parse_trojan(input: &str) -> Result<Value, ProxyParseError> {
    let url = Url::parse(input).map_err(ProxyParseError::Url)?;
    let password = url.username();
    if password.is_empty() {
        return Err(ProxyParseError::MissingField("password"));
    }
    let (server, port) = host_port(&url)?;
    let params: BTreeMap<String, String> = url.query_pairs().into_owned().collect();
    let network = param(&params, "type").unwrap_or("tcp");

    let mut proxy = Map::new();
    proxy.insert("type".into(), json!("trojan"));
    proxy.insert("server".into(), json!(server));
    proxy.insert("port".into(), json!(port));
    proxy.insert("password".into(), json!(password));
    proxy.insert("udp".into(), json!(true));
    // Trojan is TLS by definition.
    if let Some(sni) = param(&params, "sni").or_else(|| param(&params, "peer")) {
        proxy.insert("sni".into(), json!(sni));
    }
    if let Some(fingerprint) = param(&params, "fp") {
        proxy.insert("client-fingerprint".into(), json!(fingerprint));
    }
    if param(&params, "allowInsecure").is_some_and(|value| value == "1" || value == "true") {
        proxy.insert("skip-cert-verify".into(), json!(true));
    }
    apply_transport(&mut proxy, &params, network);
    if network != "tcp" {
        proxy.insert("network".into(), json!(network));
    }
    attach_remark(&mut proxy, &url);
    Ok(Value::Object(proxy))
}

fn parse_shadowsocks(input: &str) -> Result<Value, ProxyParseError> {
    // Two encodings exist: `ss://base64(method:password)@host:port#name` and
    // `ss://base64(method:password@host:port)#name`. Handle both.
    let without_scheme = input.trim_start_matches("ss://");
    let (main, fragment) = match without_scheme.split_once('#') {
        Some((main, fragment)) => (main, Some(fragment)),
        None => (without_scheme, None),
    };
    let main = main.split('?').next().unwrap_or(main);

    let (method, password, server, port) = if let Some((userinfo, hostinfo)) = main.split_once('@')
    {
        // userinfo may be base64 or plain `method:password`.
        let creds = decode_base64(userinfo).unwrap_or_else(|| userinfo.to_owned());
        let (method, password) = creds
            .split_once(':')
            .ok_or(ProxyParseError::MissingField("ss method:password"))?;
        let (server, port) = split_host_port(hostinfo)?;
        (method.to_owned(), password.to_owned(), server, port)
    } else {
        // Whole thing is base64.
        let decoded = decode_base64(main).ok_or(ProxyParseError::InvalidBase64)?;
        let (creds, hostinfo) = decoded
            .split_once('@')
            .ok_or(ProxyParseError::MissingField("ss userinfo"))?;
        let (method, password) = creds
            .split_once(':')
            .ok_or(ProxyParseError::MissingField("ss method:password"))?;
        let (server, port) = split_host_port(hostinfo)?;
        (method.to_owned(), password.to_owned(), server, port)
    };

    let mut proxy = Map::new();
    proxy.insert("type".into(), json!("ss"));
    proxy.insert("server".into(), json!(server));
    proxy.insert("port".into(), json!(port));
    proxy.insert("cipher".into(), json!(method));
    proxy.insert("password".into(), json!(password));
    proxy.insert("udp".into(), json!(true));
    if let Some(fragment) = fragment {
        proxy.insert("__remark".into(), json!(percent_decode(fragment)));
    }
    Ok(Value::Object(proxy))
}

fn parse_hysteria2(input: &str) -> Result<Value, ProxyParseError> {
    let url = Url::parse(input).map_err(ProxyParseError::Url)?;
    let password = url.username();
    if password.is_empty() {
        return Err(ProxyParseError::MissingField("password"));
    }
    let (server, port) = host_port(&url)?;
    let params: BTreeMap<String, String> = url.query_pairs().into_owned().collect();

    let mut proxy = Map::new();
    proxy.insert("type".into(), json!("hysteria2"));
    proxy.insert("server".into(), json!(server));
    proxy.insert("port".into(), json!(port));
    proxy.insert("password".into(), json!(password));
    if let Some(sni) = param(&params, "sni") {
        proxy.insert("sni".into(), json!(sni));
    }
    if let Some(obfs) = param(&params, "obfs") {
        proxy.insert("obfs".into(), json!(obfs));
        if let Some(obfs_password) = param(&params, "obfs-password") {
            proxy.insert("obfs-password".into(), json!(obfs_password));
        }
    }
    if param(&params, "insecure").is_some_and(|value| value == "1" || value == "true") {
        proxy.insert("skip-cert-verify".into(), json!(true));
    }
    attach_remark(&mut proxy, &url);
    Ok(Value::Object(proxy))
}

/// Fill in `tls`/`servername`/`client-fingerprint` and `reality-opts` for VLESS
/// based on the `security` query parameter.
fn apply_tls_and_reality(
    proxy: &mut Map<String, Value>,
    params: &BTreeMap<String, String>,
    security: &str,
    server: &str,
) {
    if security != "tls" && security != "reality" {
        return;
    }
    proxy.insert("tls".into(), json!(true));
    let servername = param(params, "sni").unwrap_or(server);
    proxy.insert("servername".into(), json!(servername));
    if let Some(fingerprint) = param(params, "fp") {
        proxy.insert("client-fingerprint".into(), json!(fingerprint));
    }
    if security == "reality" {
        let mut reality = Map::new();
        if let Some(public_key) = param(params, "pbk") {
            reality.insert("public-key".into(), json!(public_key));
        }
        if let Some(short_id) = param(params, "sid") {
            reality.insert("short-id".into(), json!(short_id));
        }
        proxy.insert("reality-opts".into(), Value::Object(reality));
    }
}

/// Fill in `ws-opts`/`grpc-opts` from the `path`/`host`/`serviceName` query
/// parameters for ws and grpc transports.
fn apply_transport(
    proxy: &mut Map<String, Value>,
    params: &BTreeMap<String, String>,
    network: &str,
) {
    match network {
        "ws" => {
            let mut ws = Map::new();
            ws.insert("path".into(), json!(param(params, "path").unwrap_or("/")));
            if let Some(host) = param(params, "host").or_else(|| param(params, "authority")) {
                ws.insert("headers".into(), json!({ "Host": host }));
            }
            proxy.insert("ws-opts".into(), Value::Object(ws));
        }
        "grpc" => {
            if let Some(service_name) =
                param(params, "serviceName").or_else(|| param(params, "servicename"))
            {
                proxy.insert(
                    "grpc-opts".into(),
                    json!({ "grpc-service-name": service_name }),
                );
            }
        }
        _ => {}
    }
}

fn attach_remark(proxy: &mut Map<String, Value>, url: &Url) {
    if let Some(fragment) = url.fragment() {
        let remark = percent_decode(fragment);
        if !remark.trim().is_empty() {
            proxy.insert("__remark".into(), json!(remark));
        }
    }
}

fn host_port(url: &Url) -> Result<(String, u16), ProxyParseError> {
    let host = url
        .host_str()
        .ok_or(ProxyParseError::MissingField("host"))?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = url.port().ok_or(ProxyParseError::MissingField("port"))?;
    Ok((host, port))
}

fn split_host_port(hostinfo: &str) -> Result<(String, u16), ProxyParseError> {
    let hostinfo = hostinfo.split(['?', '#', '/']).next().unwrap_or(hostinfo);
    let (host, port) = hostinfo
        .rsplit_once(':')
        .ok_or(ProxyParseError::MissingField("host:port"))?;
    let port = port
        .trim()
        .parse::<u16>()
        .map_err(|_| ProxyParseError::MissingField("port"))?;
    Ok((host.trim_matches(['[', ']']).to_owned(), port))
}

fn param<'a>(params: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    params
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn str_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(text) = value.get(key).and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

fn port_field(value: &Value, keys: &[&str]) -> Option<u16> {
    for key in keys {
        if let Some(port) = value.get(key).and_then(Value::as_u64)
            && let Ok(port) = u16::try_from(port)
        {
            return Some(port);
        }
        if let Some(text) = value.get(key).and_then(Value::as_str)
            && let Ok(port) = text.trim().parse::<u16>()
        {
            return Some(port);
        }
    }
    None
}

fn decode_base64(value: &str) -> Option<String> {
    let value = value.trim();
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

fn percent_decode(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

#[derive(Debug, Error)]
pub enum ProxyParseError {
    #[error("proxy URI is missing a scheme")]
    MissingScheme,
    #[error("unsupported proxy scheme: {0}")]
    UnsupportedScheme(String),
    #[error("invalid proxy URI: {0}")]
    Url(url::ParseError),
    #[error("proxy URI is missing required field: {0}")]
    MissingField(&'static str),
    #[error("proxy URI has invalid base64 payload")]
    InvalidBase64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reality_vless() {
        let proxy = proxy_from_uri("vless://00000000-0000-0000-0000-000000000000@example.com:443?encryption=none&type=tcp&security=reality&sni=example.com&fp=firefox&pbk=KEY&sid=0ff1#%F0%9F%87%AB%F0%9F%87%AEFinland").expect("vless should parse");
        assert_eq!(proxy["type"], json!("vless"));
        assert_eq!(proxy["server"], json!("example.com"));
        assert_eq!(proxy["port"], json!(443));
        assert_eq!(proxy["tls"], json!(true));
        assert_eq!(proxy["client-fingerprint"], json!("firefox"));
        assert_eq!(proxy["reality-opts"]["public-key"], json!("KEY"));
        assert_eq!(proxy["reality-opts"]["short-id"], json!("0ff1"));
        assert_eq!(proxy_display_name(&proxy), "🇫🇮Finland");
    }

    #[test]
    fn parses_vless_ws_tls() {
        let proxy = proxy_from_uri("vless://uuid-here@example.com:443?type=ws&security=tls&sni=example.com&path=%2Fpath&host=cdn.example.com").expect("vless ws should parse");
        assert_eq!(proxy["network"], json!("ws"));
        assert_eq!(proxy["ws-opts"]["path"], json!("/path"));
        assert_eq!(
            proxy["ws-opts"]["headers"]["Host"],
            json!("cdn.example.com")
        );
    }

    #[test]
    fn parses_trojan() {
        let proxy = proxy_from_uri("trojan://secret@example.com:443?sni=example.com#Node")
            .expect("trojan should parse");
        assert_eq!(proxy["type"], json!("trojan"));
        assert_eq!(proxy["password"], json!("secret"));
        assert_eq!(proxy["sni"], json!("example.com"));
        assert_eq!(proxy_display_name(&proxy), "Node");
    }

    #[test]
    fn parses_shadowsocks_plain_userinfo() {
        // ss://base64(method:password)@host:port#name
        let userinfo = general_purpose::STANDARD.encode("aes-256-gcm:pass123");
        let uri = format!("ss://{userinfo}@example.com:8388#SS-Node");
        let proxy = proxy_from_uri(&uri).expect("ss should parse");
        assert_eq!(proxy["type"], json!("ss"));
        assert_eq!(proxy["cipher"], json!("aes-256-gcm"));
        assert_eq!(proxy["password"], json!("pass123"));
        assert_eq!(proxy["port"], json!(8388));
        assert_eq!(proxy_display_name(&proxy), "SS-Node");
    }

    #[test]
    fn parses_hysteria2() {
        let proxy = proxy_from_uri("hysteria2://pass@example.com:443?sni=example.com&obfs=salamander&obfs-password=xyz#HY2").expect("hy2 should parse");
        assert_eq!(proxy["type"], json!("hysteria2"));
        assert_eq!(proxy["password"], json!("pass"));
        assert_eq!(proxy["obfs"], json!("salamander"));
        assert_eq!(proxy["obfs-password"], json!("xyz"));
    }

    #[test]
    fn rejects_unknown_scheme() {
        let error = proxy_from_uri("wireguard://foo").expect_err("scheme should fail");
        assert!(matches!(error, ProxyParseError::UnsupportedScheme(_)));
    }
}
