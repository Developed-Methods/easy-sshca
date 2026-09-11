//! Unauthenticated HTTPS endpoints: health checks, zone CA public keys and metrics.

use crate::{
    auth,
    error::Error,
    protocol::{Command, Operation},
    server::State as ServerState,
};
use axum::{
    Router,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use std::{fmt::Write, net::SocketAddr, sync::atomic::Ordering};

pub fn router(state: ServerState) -> Router {
    Router::new()
        .route("/health/live", get(|| async { "live\n" }))
        .route("/health/ready", get(ready))
        .route("/zones/{name}/ca.pub", get(public_key))
        .with_state(state)
}

pub fn metrics_router(state: ServerState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn ready(State(state): State<ServerState>) -> Response {
    if state.is_ready() {
        (StatusCode::OK, "ready\n").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "locked\n").into_response()
    }
}

async fn public_key(
    State(state): State<ServerState>,
    Path(zone): Path<String>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let command = Command {
        request_id: auth::new_id(),
        zone,
        ..Default::default()
    };
    let reply = state
        .call(
            Operation::GetPublicKey,
            String::new(),
            command,
            Some(source.ip()),
        )
        .await;
    let reply = match reply {
        Ok(reply) => reply,
        Err(error) => return rejection(&error),
    };
    let etag = format!("\"{}\"", reply.fingerprint);
    let cached = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| etag_matches(value, &etag));
    let (status, body) = if cached {
        (StatusCode::NOT_MODIFIED, String::new())
    } else {
        (StatusCode::OK, format!("{}\n", reply.public_key))
    };
    tracing::info!(
        status = status.as_u16(),
        result = "OK",
        "Public CA request completed"
    );
    (
        status,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_owned()),
            (header::ETAG, etag),
            (header::CACHE_CONTROL, "public, no-cache".to_owned()),
        ],
        body,
    )
        .into_response()
}

/// Whether an `If-None-Match` header names `etag`, as a strong or weak tag.
fn etag_matches(header: &str, etag: &str) -> bool {
    header.split(',').map(str::trim).any(|candidate| {
        candidate == etag || candidate == "*" || candidate.strip_prefix("W/") == Some(etag)
    })
}

fn rejection(error: &Error) -> Response {
    use tonic::Code;
    let status = match error.code {
        Code::NotFound => StatusCode::NOT_FOUND,
        Code::InvalidArgument => StatusCode::BAD_REQUEST,
        Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    if matches!(error.code, Code::Internal | Code::Unavailable) {
        tracing::error!(
            status = status.as_u16(),
            result = error.reason,
            "Public CA request failed"
        );
    } else {
        tracing::warn!(
            status = status.as_u16(),
            result = error.reason,
            "Public CA request rejected"
        );
    }
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        error.message.clone(),
    )
        .into_response()
}

async fn metrics(State(state): State<ServerState>) -> Response {
    let metrics = &state.metrics;
    let mut body = String::new();
    let gauges = [
        ("easy_sshca_ready", u64::from(state.is_ready())),
        (
            "easy_sshca_database_queue_depth",
            state.queue_depth() as u64,
        ),
        (
            "easy_sshca_requests_total",
            metrics.requests.load(Ordering::Relaxed),
        ),
        (
            "easy_sshca_failures_total",
            metrics.failures.load(Ordering::Relaxed),
        ),
        (
            "easy_sshca_issued_certificates_total",
            metrics.issued.load(Ordering::Relaxed),
        ),
        (
            "easy_sshca_rate_limit_rejections_total",
            metrics.rate_limited.load(Ordering::Relaxed),
        ),
    ];
    for (name, value) in gauges {
        let _ = writeln!(body, "{name} {value}");
    }
    let _ = writeln!(
        body,
        "easy_sshca_request_duration_seconds_sum {}",
        seconds(metrics.micros.load(Ordering::Relaxed))
    );
    for (operation, reason, outcome) in metrics.outcomes() {
        let labels = format!("{{operation=\"{operation}\",reason=\"{reason}\"}}");
        let _ = writeln!(
            body,
            "easy_sshca_operations_total{labels} {}",
            outcome.count
        );
        let _ = writeln!(
            body,
            "easy_sshca_operation_duration_seconds_sum{labels} {}",
            seconds(outcome.micros)
        );
    }
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

fn seconds(micros: u64) -> f64 {
    micros as f64 / 1e6
}
