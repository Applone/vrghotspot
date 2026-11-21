use async_trait::async_trait;
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
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

    pub fn display(&self) -> String {
        self.0.to_string()
    }
}

pub fn configured_value(name: &str, compiled: Option<&str>) -> Option<String> {
    std::env::var(name)
        .ok()
        .or_else(|| compiled.map(str::to_owned))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Build-time values only: endpoints are baked into the binary at compile time
/// and cannot be redirected by the runtime environment.
pub fn build_value(compiled: Option<&str>) -> Option<String> {
    compiled
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
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

#[derive(Clone)]
pub struct OtlpHttpClient {
    pub client: reqwest::Client,
    pub endpoint: Url,
    pub token: Option<String>,
}

impl std::fmt::Debug for OtlpHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OtlpHttpClient")
    }
}

#[async_trait]
impl HttpClient for OtlpHttpClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let mut outgoing = self
            .client
            .post(self.endpoint.clone())
            .header("Content-Type", "application/x-protobuf")
            .body(request.into_body());
        if let Some(token) = &self.token {
            outgoing = outgoing.bearer_auth(token);
        }
        let response = outgoing.send().await.map_err(reqwest::Error::without_url)?;
        let status = response.status();
        // The OTLP retry layer reads `Retry-After` from response headers to
        // honor collector backpressure; rebuild the response with them intact.
        let headers = response.headers().clone();
        let body = limited_body(response)
            .await
            .map_err(std::io::Error::other)?;
        let mut outgoing = Response::builder().status(status);
        for (name, value) in &headers {
            outgoing = outgoing.header(name, value);
        }
        Ok(outgoing.body(Bytes::from(body))?)
    }
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
        assert_eq!(endpoint.url("v1/metrics").path(), "/telemetry/v1/metrics");
        assert!(Endpoint::parse("http://127.0.0.1:4318").is_ok());
        assert!(Endpoint::parse("http://[::1]:4318").is_ok());
    }

    #[test]
    fn transport_debug_never_contains_credentials() {
        let transport = OtlpHttpClient {
            client: client().unwrap(),
            endpoint: Endpoint::parse("http://127.0.0.1:4318")
                .unwrap()
                .url("v1/metrics"),
            token: Some("private-token".to_owned()),
        };
        assert_eq!(format!("{transport:?}"), "OtlpHttpClient");
    }

    #[tokio::test]
    async fn response_headers_reach_the_exporter_throttle_logic() {
        let server = super::super::test_server::TestServer::new(false, Duration::ZERO).await;
        let transport = OtlpHttpClient {
            client: client().unwrap(),
            endpoint: server.endpoint.url("v1/metrics"),
            token: None,
        };
        let response = transport
            .send_bytes(Request::builder().body(Bytes::new()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()["location"], "/redirected");
    }
}
