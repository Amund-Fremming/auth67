use std::sync::Arc;

use axum::{
    Extension, Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get,
};

use crate::{db, error::ServerError, models::auth::Claims, state::AppState};

pub fn user_routes(state: Arc<AppState>) -> Router {
    Router::new().route("/me", get(me)).with_state(state)
}

async fn me(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, ServerError> {
    let user_id = claims.user_id()?;
    match db::user::get_user(state.get_pool(), user_id).await? {
        Some(user) => Ok((StatusCode::OK, Json(user))),
        None => Err(ServerError::Http(
            StatusCode::NOT_FOUND,
            "User not found".to_string(),
        )),
    }
}
