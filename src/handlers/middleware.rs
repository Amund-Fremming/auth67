use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::Response,
};
use tracing::warn;

use crate::{error::ServerError, state::AppState};

pub(crate) async fn auth_mw(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, ServerError> {
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let Some(token) = token else {
        warn!("Missing or invalid Authorization header");
        return Err(ServerError::Http(
            StatusCode::UNAUTHORIZED,
            "Unauthorized".to_string(),
        ));
    };

    let claims = state.auth.validate_token(token)?;

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
