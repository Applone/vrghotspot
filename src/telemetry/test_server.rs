use super::transport::Endpoint;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct CapturedRequest {
    pub path: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Clone, Default)]
struct ServerState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    reply: Arc<Mutex<(u16, Vec<u8>)>>,
    metrics_fail: bool,
    delay: Duration,
    received: Arc<Notify>,
}

pub struct TestServer {
    pub endpoint: Endpoint,
    state: ServerState,
    task: JoinHandle<()>,
}

impl TestServer {
    pub async fn new(metrics_fail: bool, delay: Duration) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut url = Endpoint::parse("http://127.0.0.1/").unwrap().url("");
        url.set_port(Some(address.port())).unwrap();
        let endpoint = Endpoint::parse(url.as_str()).unwrap();
        let state = ServerState {
            metrics_fail,
            delay,
            ..Default::default()
        };
        *state.reply.lock().unwrap() = (200, Vec::new());
        let router = Router::new()
            .route("/{*path}", post(receive))
            .with_state(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            endpoint,
            state,
            task,
        }
    }

    pub fn reply(&self, status: u16, body: Vec<u8>) {
        *self.state.reply.lock().unwrap() = (status, body);
    }

    pub fn requests(&self) -> Vec<CapturedRequest> {
        self.state.requests.lock().unwrap().clone()
    }

    pub async fn wait_for_requests(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let received = self.state.received.notified();
                if self.requests().len() >= count {
                    return;
                }
                received.await;
            }
        })
        .await
        .expect("test server request timeout");
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn receive(
    State(state): State<ServerState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state.requests.lock().unwrap().push(CapturedRequest {
        path: uri.path().to_owned(),
        headers,
        body: body.to_vec(),
    });
    state.received.notify_one();
    tokio::time::sleep(state.delay).await;
    let (status, body) = state.reply.lock().unwrap().clone();
    let status = if state.metrics_fail && uri.path().ends_with("/metrics") {
        400
    } else {
        status
    };
    (
        StatusCode::from_u16(status).unwrap(),
        [("location", "/redirected")],
        body,
    )
        .into_response()
}
