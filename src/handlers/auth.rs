use std::sync::Arc;

use validator::Validate;

use crate::{
    handlers::extract_user_agent,
    models::auth::{Claims, LogoutRequest, RefreshTokenRequest},
    models::user::LoginRequest,
};
use axum::{
    Extension, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};

use crate::{
    db,
    error::ServerError,
    models::{
        otp::{CreateOtpRequest, VerifyOtpRequest},
        user::SignupRequest,
    },
    state::AppState,
};

pub fn public_auth_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/signup", post(signup))
        .route("/refresh", post(refresh_tokens))
        .route("/otp", post(create_otp))
        .route("/otp/verify", post(verify_otp))
        .with_state(state)
}

pub fn protected_auth_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/sessions", get(list_sessions))
        .route("/logout", post(logout))
        .with_state(state)
}

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, ServerError> {
    let user_id = claims.user_id()?;
    let sessions = db::auth::list_session_dtos(state.get_pool(), user_id).await?;
    Ok((StatusCode::OK, Json(sessions)))
}

async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<LogoutRequest>,
) -> Result<impl IntoResponse, ServerError> {
    let user_id = claims.user_id()?;
    state.auth.logout(user_id, req.device_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, ServerError> {
    req.validate()
        .map_err(|e| ServerError::Validation(e.to_string()))?;

    let user_agent = extract_user_agent(&headers);
    let token_response = state
        .auth
        .login(
            req.device_id,
            &req.device_name,
            user_agent,
            &req.identifier,
            req.provider_type,
            &req.password,
        )
        .await?;

    Ok((StatusCode::OK, Json(token_response)))
}

async fn signup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SignupRequest>,
) -> Result<impl IntoResponse, ServerError> {
    req.validate()
        .map_err(|e| ServerError::Validation(e.to_string()))?;

    let otp = db::otp::get_otp_by_identifier(state.get_pool(), &req.identifier, req.provider_type)
        .await?;
    let user_agent = extract_user_agent(&headers);

    let response = state
        .auth
        .signup(
            otp.id,
            req.provider_type,
            &req.device_name,
            user_agent,
            &req.given_name,
            &req.family_name,
            &req.password,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(response)))
}

async fn create_otp(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateOtpRequest>,
) -> Result<impl IntoResponse, ServerError> {
    req.validate()
        .map_err(|e| ServerError::Validation(e.to_string()))?;

    let response = state
        .otp
        .create_and_send(&req.phone_number, req.provider_type)
        .await?;

    Ok((StatusCode::CREATED, Json(response)))
}

// TODO - find subsctitute for ip address field on otp, moviles on 5g have misleading ip
async fn verify_otp(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyOtpRequest>,
) -> Result<impl IntoResponse, ServerError> {
    req.validate()
        .map_err(|e| ServerError::Validation(e.to_string()))?;

    state.otp.verify(req.otp_id, &req.code).await?;
    Ok(StatusCode::OK)
}

async fn refresh_tokens(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, ServerError> {
    let response = state
        .auth
        .refresh_token(req.device_id, &req.refresh_token)
        .await?;

    Ok((StatusCode::OK, Json(response)))
}
