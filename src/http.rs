use crate::{protocol::Command, server::State as ServerState};
use axum::{
    Router,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use std::sync::atomic::Ordering;
pub fn router(state: ServerState) -> Router {
    Router::new()
        .route("/health/live", get(|| async { "live\n" }))
        .route("/health/ready", get(ready))
        .route("/zones/{name}/ca.pub", get(public))
        .route("/metrics", get(metrics))
        .with_state(state)
}
async fn ready(State(state): State<ServerState>) -> Response {
    if state.ready.load(Ordering::Acquire) {
        (StatusCode::OK, "ready\n").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "locked\n").into_response()
    }
}
async fn public(
    State(state): State<ServerState>,
    Path(name): Path<String>,
    ConnectInfo(source): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let reply = state
        .call(
            "GetPublicKey",
            String::new(),
            Command {
                request_id: crate::auth::id(),
                zone: name,
                ..Default::default()
            },
            Some(source.ip()),
        )
        .await;
    match reply {
        Ok(reply) => {
            let etag = format!("\"{}\"", reply.fingerprint);
            let cached = headers
                .get(header::IF_NONE_MATCH)
                .and_then(|x| x.to_str().ok())
                .is_some_and(|x| {
                    x.split(',').any(|v| {
                        v.trim() == etag || v.trim() == format!("W/{etag}") || v.trim() == "*"
                    })
                });
            let status = if cached {
                StatusCode::NOT_MODIFIED
            } else {
                StatusCode::OK
            };
            (
                status,
                [
                    (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_owned()),
                    (header::ETAG, etag),
                    (header::CACHE_CONTROL, "public, no-cache".to_owned()),
                ],
                if cached {
                    String::new()
                } else {
                    format!("{}\n", reply.public_key)
                },
            )
                .into_response()
        }
        Err(e) => {
            let code = match e.code {
                tonic::Code::NotFound => StatusCode::NOT_FOUND,
                tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
                tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            (code, [(header::CACHE_CONTROL, "no-store")], e.message).into_response()
        }
    }
}
async fn metrics(State(s): State<ServerState>) -> Response {
    let mut body = format!(
        "easy_sshca_ready {}\neasy_sshca_database_queue_depth {}\neasy_sshca_requests_total {}\neasy_sshca_failures_total {}\neasy_sshca_issued_certificates_total {}\neasy_sshca_rate_limit_rejections_total {}\neasy_sshca_request_duration_seconds_sum {}\n",
        u8::from(s.ready.load(Ordering::Acquire)),
        s.queue_depth(),
        s.metrics.requests.load(Ordering::Relaxed),
        s.metrics.failures.load(Ordering::Relaxed),
        s.metrics.issued.load(Ordering::Relaxed),
        s.metrics.rate_limited.load(Ordering::Relaxed),
        s.metrics.micros.load(Ordering::Relaxed) as f64 / 1e6
    );
    if let Ok(outcomes) = s.metrics.outcomes.lock() {
        for ((operation, reason), (count, micros)) in outcomes.iter() {
            body.push_str(&format!("easy_sshca_operations_total{{operation=\"{operation}\",reason=\"{reason}\"}} {count}\neasy_sshca_operation_duration_seconds_sum{{operation=\"{operation}\",reason=\"{reason}\"}} {}\n",*micros as f64/1e6));
        }
    }
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}
