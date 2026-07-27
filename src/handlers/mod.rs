use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method},
    middleware as axum_mw,
    response::IntoResponse,
    routing::get,
};
use serde_json::json;
use tower_http::{
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};

use crate::{
    handlers::{
        audit::audit_routes,
        auth::{protected_auth_routes, public_auth_routes},
        middleware::auth_mw,
        user::user_routes,
    },
    state::AppState,
};

pub mod audit;
pub mod auth;
pub mod middleware;
pub mod user;

pub fn extract_user_agent(headers: &HeaderMap) -> Option<&str> {
    headers.get("user-agent").and_then(|v| v.to_str().ok())
}

async fn health() -> impl IntoResponse {
    Json(json!({ "health": "OK" }))
}

async fn well_known_jwks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.auth.get_jwks().clone())
}

pub fn app_routes(state: Arc<AppState>) -> Router {
    let public_routes: Router = Router::new()
        .route("/health", get(health))
        .route("/.well-known/jwks.json", get(well_known_jwks))
        .with_state(state.clone())
        .nest("/auth", public_auth_routes(state.clone()));

    let protected_routes: Router = Router::new()
        .nest("/user", user_routes(state.clone()))
        .nest("/audit", audit_routes(state.clone()))
        .nest("/auth", protected_auth_routes(state.clone()))
        .layer(axum_mw::from_fn_with_state(state, auth_mw));

    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any)
        .allow_origin(Any);

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        ))
}
