use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::LazyLock;

const MAX_SECRET_BYTES: usize = 4 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 1024 * 1024;

static PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>\"']+"#, "[redacted-url]"),
        (r#"(?i)\b(?:authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic)?\s*[^\s,;]+"#, "[redacted-auth]"),
        (r#"(?i)\b(?:[a-z]+[_-])*(?:password|passwd|passphrase|psk|token|secret|uuid|ssid|private[-_]?key|public[-_]?key|short[-_]?id|subscription[-_]?url|source[-_]?url|profile[-_]?name|profile[-_]?id)[\s\"']*[:=]\s*(?:\"(?:\\.|[^\"])*\"|'[^']*'|[^\r\n,;}\]]+)"#, "[redacted-field]"),
        (r#"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#, "[redacted-id]"),
        (r#"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b"#, "[redacted-mac]"),
        (r#"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?\b"#, "[redacted-ip]"),
        (r#"(?i)(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*(?:%[a-z0-9]+)?"#, "[redacted-ip]"),
        (r#"(?:/home/|/root/|/run/user/|/Users/)[^\s\"'<>]+"#, "[redacted-path]"),
        (r#"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"#, "[redacted-email]"),
        (r#"(?i)\b(?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,}(?::[0-9]+)?\b"#, "[redacted-host]"),
        (r#"\b[A-Za-z0-9_+/=-]{32,}\b"#, "[redacted-token]"),
    ]
    .into_iter()
    .map(|(pattern, replacement)| (Regex::new(pattern).expect("static privacy pattern"), replacement))
    .collect()
});

#[derive(Clone, Default)]
pub struct Redactor {
    secrets: HashSet<String>,
    bytes: usize,
    saturated: bool,
}

impl Redactor {
    pub fn remember(&mut self, value: &str) {
        if value.is_empty() || self.secrets.contains(value) || self.saturated {
            return;
        }
        if self.bytes + value.len() > MAX_SECRET_BYTES {
            self.saturated = true;
            return;
        }
        self.bytes += value.len();
        self.secrets.insert(value.to_owned());
    }

    pub fn remember_json(&mut self, value: &Value) {
        match value {
            Value::String(value) => {
                self.remember(value);
                if let Ok(escaped) = serde_json::to_string(value) {
                    self.remember(&escaped[1..escaped.len() - 1]);
                }
                self.remember(&percent_encoding::percent_decode_str(value).decode_utf8_lossy());
            }
            Value::Array(values) => {
                for value in values {
                    self.remember_json(value);
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    self.remember_json(value);
                }
            }
            _ => {}
        }
    }

    pub fn redact(&self, message: &str) -> String {
        if self.saturated || message.len() > MAX_INPUT_BYTES {
            return "[redacted: privacy size limit]".to_owned();
        }
        let mut secrets = self.secrets.iter().collect::<Vec<_>>();
        secrets.sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));
        // Multi-part values (with spaces, commas, ...) cannot survive the field
        // patterns below: those stop at the first punctuation and would eat the
        // head of e.g. the remembered SSID "Office, Alice", leaving the tail.
        // Remove such values first. Plain single-word values wait until after
        // the patterns so a remembered scheme like "http" cannot cut a URL in
        // half and leave its credentials unmatched.
        let mut output = message.to_owned();
        let mut plain = Vec::new();
        for secret in secrets {
            if secret
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
            {
                plain.push(secret);
            } else {
                output = output.replace(secret.as_str(), "[redacted]");
            }
        }
        for (pattern, replacement) in PATTERNS.iter() {
            output = pattern.replace_all(&output, *replacement).into_owned();
        }
        for secret in plain {
            output = output.replace(secret.as_str(), "[redacted]");
        }
        output
    }
}

pub fn truncate(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let mut end = limit.saturating_sub(3);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_credentials_network_identifiers_and_user_paths() {
        let mut redactor = Redactor::default();
        redactor.remember("My private network");
        redactor.remember_json(&serde_json::json!({"password": "old password with spaces", "nested": {"key": "secret\\\"value"}}));
        let input = r#"failed My private network password="old password with spaces" token=abc123 uuid=550e8400-e29b-41d4-a716-446655440000 https://user:password@cp.cloudflare.com/token?q=abc vless://private@10.1.2.3:443/a 192.168.1.2:9000 [2001:db8::1] aa:bb:cc:dd:ee:ff /home/alice/settings.json someone@private.example.com server.private.example.com authorization: Bearer opaque-token"#;
        let output = redactor.redact(input);
        for secret in [
            "My private",
            "old password",
            "abc123",
            "550e8400",
            "cloudflare",
            "10.1.2",
            "192.168",
            "2001:db8",
            "aa:bb",
            "alice",
            "private.example",
            "opaque-token",
        ] {
            assert!(!output.contains(secret), "{secret} in {output}");
        }
        assert!(output.starts_with("failed"));
    }

    #[test]
    fn remembers_historical_and_escaped_values() {
        let mut redactor = Redactor::default();
        redactor.remember_json(
            &serde_json::json!({"ssid": "старое имя", "password": "secret\"phrase"}),
        );
        redactor.remember_json(&serde_json::json!({"ssid": "new network"}));
        assert!(
            !redactor
                .redact("старое имя new network secret\\\"phrase")
                .contains("secret")
        );
        assert!(!redactor.redact("старое имя new network").contains("имя"));
    }

    #[test]
    fn remembered_schemes_cannot_expose_url_credentials() {
        let mut redactor = Redactor::default();
        redactor.remember("http");
        redactor.remember("cp.cloudflare.com");
        let output = redactor.redact("http://alice:shortpass@cp.cloudflare.com/private-token");
        assert!(!output.contains("alice"));
        assert!(!output.contains("shortpass"));
        assert!(!output.contains("private-token"));
    }

    #[test]
    fn redacts_prefixed_fields_and_short_values() {
        let mut redactor = Redactor::default();
        redactor.remember("xy");
        let output = redactor.redact("hotspot_ssid=New Name, hotspot_passphrase=short phrase; xy");
        assert!(!output.contains("New Name"));
        assert!(!output.contains("short phrase"));
        assert!(!output.contains("xy"));
    }

    #[test]
    fn remembered_values_with_punctuation_are_removed_before_field_patterns() {
        let mut redactor = Redactor::default();
        redactor.remember("Office, Alice");
        let output = redactor.redact("hotspot_ssid=Office, Alice failed to start");
        assert!(!output.contains("Alice"), "{output}");
        assert!(!output.contains("Office"), "{output}");
    }

    #[test]
    fn oversized_input_is_omitted_not_partially_leaked() {
        assert_eq!(
            Redactor::default().redact(&"a".repeat(MAX_INPUT_BYTES + 1)),
            "[redacted: privacy size limit]"
        );
        let output = truncate("парольпарольпароль", 16);
        assert!(output.len() <= 16);
        assert!(output.ends_with("..."));
    }
}
