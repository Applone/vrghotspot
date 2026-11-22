use std::time::Duration;
use url::{Host, Url};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct Endpoint(Url);

impl Endpoint {
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut url = Url::parse(value).map_err(|_| "invalid telemetry server address")?;
        let loopback = match url.host() {
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
        if url.host().is_none()
            || !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("telemetry server must use HTTPS without credentials, a query or a fragment (HTTP is allowed only on loopback)".to_owned());
        }
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }
        Ok(Self(url))
    }

    pub fn url(&self, path: &str) -> Url {
        self.0.join(path).expect("static telemetry endpoint path")
    }
}

pub fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("vrghotspot/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.without_url().to_string())
}

pub async fn limited_body(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| error.without_url().to_string())?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err("telemetry response exceeds size limit".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_validation_fails_closed() {
        for value in [
            "http://cp.cloudflare.com/",
            "https://user:secret@cp.cloudflare.com/",
            "https://cp.cloudflare.com/?token=secret",
            "https://cp.cloudflare.com/#fragment",
            "file:///tmp/report",
            "http://localhost:4318",
        ] {
            assert!(Endpoint::parse(value).is_err(), "{value}");
        }
        let endpoint = Endpoint::parse("https://cp.cloudflare.com/telemetry").unwrap();
        assert_eq!(endpoint.url("v1/reports").path(), "/telemetry/v1/reports");
        assert!(Endpoint::parse("http://127.0.0.1:4318").is_ok());
        assert!(Endpoint::parse("http://[::1]:4318").is_ok());
    }

    #[tokio::test]
    async fn report_uploads_do_not_follow_redirects() {
        let server = super::super::test_server::TestServer::new().await;
        server.reply(307, Vec::new());
        let response = client()
            .unwrap()
            .post(server.endpoint.url("v1/reports"))
            .body("test report")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 307);
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/reports");
    }
}
