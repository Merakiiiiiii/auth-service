use crate::application::HealthProbe;
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde_json::{Value, json};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
struct HttpState {
    health: Arc<dyn HealthProbe>,
}

pub fn router(health: Arc<dyn HealthProbe>) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .with_state(HttpState { health })
        .layer(TraceLayer::new_for_http())
}

async fn live() -> Json<Value> {
    Json(json!({"status": "live", "service": "auth-service"}))
}

async fn ready(State(state): State<HttpState>) -> impl IntoResponse {
    match state.health.ping().await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"status": "ready", "database": "available"})),
        ),
        Err(error) => {
            tracing::warn!(%error, "auth readiness database probe failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status": "not_ready", "database": "unavailable"})),
            )
        }
    }
}

async fn metrics() -> &'static str {
    "# HELP auth_service_up Process liveness.\n# TYPE auth_service_up gauge\nauth_service_up 1\n"
}
