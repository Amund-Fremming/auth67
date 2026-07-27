use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};

use crate::{
    db, error::ServerError, models::audit::AuditQuery, models::auth::Claims, state::AppState,
};

pub fn audit_routes(state: Arc<AppState>) -> Router {
    Router::new().route("/", get(list_logs)).with_state(state)
}

async fn list_logs(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(q): Query<AuditQuery>,
) -> Result<impl IntoResponse, ServerError> {
    state.require_admin(&claims)?;
    let logs = db::audit::list(state.get_pool(), q).await?;
    Ok((StatusCode::OK, Json(logs)))
}
