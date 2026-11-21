use serde_json::{Value, json};
use thiserror::Error;

/// Name of the proxy that carries all non-LAN traffic. The template's `MATCH`
/// rule points at this name and every applied profile is inserted under it.
const PROXY_NAME: &str = "proxy";
/// Applied to Mihomo-owned outbound sockets so policy routing can keep them
/// outside the TUN route they transport.
#[cfg(target_os = "linux")]
pub const MIHOMO_ROUTING_MARK: u32 = 0x6636;
/// Name of the TUN device Mihomo creates. Shared with the OS layer, which must
/// reference the same interface for firewalld zoning and nftables rules.
pub const TUN_DEVICE_NAME: &str = "vrghotspot-tun";

#[derive(Debug, Clone)]
pub struct CoreConfig {
    value: Value,
}

impl CoreConfig {
    /// The base Mihomo (Clash.Meta) client config: a TUN inbound that hijacks
    /// the default route, fake-ip DNS for reliable capture, traffic sniffing,
    /// and a rule set that keeps LAN/private traffic direct while sending
    /// everything else through the selected proxy.
    ///
    /// `proxies` starts empty; [`apply_proxy`](Self::apply_proxy) fills it in
    /// from the selected profile. The default `MATCH` rule routes directly.
    pub fn default_client_tun() -> Self {
        let mut value = json!({
            "mode": "rule",
            "log-level": "warning",
            "allow-lan": true,
            // geoip.dat/geosite.dat (not mmdb) drive the GEOIP rule below;
            // the Rust side downloads them into the home dir.
            "geodata-mode": true,
            "geodata-loader": "standard",
            "sniffer": {
                "enable": true,
                "force-dns-mapping": true,
                "parse-pure-ip": true,
                "sniff": {
                    "TLS": { "ports": [443, 8443] },
                    "HTTP": { "ports": [80, "8080-8880"], "override-destination": true },
                    "QUIC": { "ports": [443, 8443] }
                }
            },
            "tun": {
                "enable": true,
                "stack": "system",
                "device": TUN_DEVICE_NAME,
                "auto-route": true,
                "auto-detect-interface": true,
                "dns-hijack": ["any:53"]
            },
            // DNS must avoid a circular dependency: `auto-route` puts the
            // default route in the TUN, so resolving the proxy's own
            // hostname through `nameserver` would route the query into the
            // tunnel that is not up yet. `auto-detect-interface` then
            // reports `<invalid>` ("get empty name") and the tunnel never
            // establishes. Two keys break the loop:
            //   * `default-nameserver` — plain-IP resolvers used to
            //     bootstrap the DoH hostnames themselves.
            //   * `proxy-server-nameserver` — dedicated resolvers for the
            //     outbound proxy's domain, always queried directly rather
            //     than through the tunnel.
            // See https://wiki.metacubex.one/config/dns/.
            "dns": {
                "enable": true,
                "listen": "0.0.0.0:1053",
                "ipv6": true,
                "enhanced-mode": "fake-ip",
                "fake-ip-range": "198.18.0.1/16",
                "default-nameserver": ["8.8.8.8", "1.1.1.1"],
                "proxy-server-nameserver": [
                    "https://8.8.8.8/dns-query",
                    "https://1.1.1.1/dns-query"
                ],
                "nameserver": [
                    "https://1.1.1.1/dns-query",
                    "https://8.8.8.8/dns-query"
                ]
            },
            "proxies": [],
            "rules": [
                "GEOIP,lan,DIRECT,no-resolve",
                "MATCH,DIRECT"
            ]
        });
        #[cfg(target_os = "linux")]
        {
            value["routing-mark"] = json!(MIHOMO_ROUTING_MARK);
        }
        #[cfg(windows)]
        {
            value["tun"]["mtu"] = json!(1420);
        }
        Self { value }
    }

    /// Insert a Mihomo proxy node (a proxy map as produced by the subscription
    /// parser) and route all matched traffic through it. The proxy is renamed
    /// to the canonical [`PROXY_NAME`] so the template's `MATCH` rule always
    /// targets it regardless of the node's original label.
    pub fn apply_proxy(&mut self, proxy: &Value) -> Result<(), CoreConfigError> {
        let mut proxy = proxy.clone();
        let object = proxy
            .as_object_mut()
            .ok_or(CoreConfigError::InvalidProxy("proxy is not a mapping"))?;
        if !object.contains_key("type") {
            return Err(CoreConfigError::InvalidProxy("proxy is missing a `type`"));
        }
        if !object.contains_key("server") {
            return Err(CoreConfigError::InvalidProxy("proxy is missing a `server`"));
        }
        // Drop internal-only keys (e.g. `__remark`) that the parser attaches for
        // display purposes; Mihomo rejects unknown proxy fields.
        object.retain(|key, _| !key.starts_with("__"));
        object.insert("name".to_owned(), json!(PROXY_NAME));

        self.value["proxies"] = json!([proxy]);
        self.value["rules"][1] = json!(format!("MATCH,{PROXY_NAME}"));
        Ok(())
    }

    pub fn to_yaml(&self) -> Result<String, CoreConfigError> {
        serde_yaml::to_string(&self.value).map_err(CoreConfigError::Serialize)
    }

    #[cfg(test)]
    pub fn as_value(&self) -> &Value {
        &self.value
    }
}

#[derive(Debug, Error)]
pub enum CoreConfigError {
    #[error("invalid proxy configuration: {0}")]
    InvalidProxy(&'static str),
    #[error("failed to serialize Mihomo configuration to YAML: {0}")]
    Serialize(serde_yaml::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::proxy::proxy_from_uri;

    #[test]
    fn default_template_has_tun_and_rules() {
        let config = CoreConfig::default_client_tun();
        let value = config.as_value();
        assert_eq!(value["tun"]["enable"], json!(true));
        assert_eq!(value["dns"]["enhanced-mode"], json!("fake-ip"));
        #[cfg(target_os = "linux")]
        assert_eq!(value["routing-mark"], json!(MIHOMO_ROUTING_MARK));
        let rules = value["rules"].as_array().expect("rules array");
        assert_eq!(rules.last().unwrap(), &json!("MATCH,DIRECT"));
        #[cfg(windows)]
        assert_eq!(value["tun"]["mtu"], json!(1420));
    }

    #[test]
    fn dns_breaks_the_proxy_resolution_loop() {
        let config = CoreConfig::default_client_tun();
        let dns = &config.as_value()["dns"];

        // `proxy-server-nameserver` is what resolves the outbound proxy's own
        // domain outside the tunnel. Without it, `auto-route` +
        // `auto-detect-interface` deadlock and the tunnel never comes up.
        let proxy_ns = dns["proxy-server-nameserver"]
            .as_array()
            .expect("proxy-server-nameserver must be configured");
        assert!(
            !proxy_ns.is_empty(),
            "proxy-server-nameserver must not be empty"
        );

        // Plain-IP bootstrap resolvers for the DoH hostnames themselves.
        let default_ns = dns["default-nameserver"]
            .as_array()
            .expect("default-nameserver must be configured");
        assert!(
            default_ns.iter().all(|entry| {
                entry
                    .as_str()
                    .is_some_and(|value| !value.starts_with("https://"))
            }),
            "default-nameserver must use plain IPs, not DoH URLs"
        );
    }

    #[test]
    fn applies_reality_vless_proxy() {
        let proxy = proxy_from_uri("vless://00000000-0000-0000-0000-000000000000@example.com:443?encryption=none&type=tcp&security=reality&sni=example.com&fp=firefox&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0000000000000000#Finland").expect("uri should parse");

        let mut config = CoreConfig::default_client_tun();
        config.apply_proxy(&proxy).expect("proxy should apply");

        let value = config.as_value();
        let proxies = value["proxies"].as_array().expect("proxies array");
        assert_eq!(proxies.len(), 1);
        let applied = &proxies[0];
        assert_eq!(applied["name"], json!("proxy"));
        assert_eq!(value["rules"][1], json!("MATCH,proxy"));
        assert_eq!(applied["type"], json!("vless"));
        assert_eq!(applied["server"], json!("example.com"));
        assert_eq!(applied["port"], json!(443));
        assert_eq!(
            applied["reality-opts"]["public-key"],
            json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );

        // Round-trips through YAML without error.
        config.to_yaml().expect("config should serialize to YAML");
    }
}
