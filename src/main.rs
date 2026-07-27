use auth67::{
    adapters::comms::CommsAdapter, adapters::crypto::CryptoAdapter, config::CONFIG,
    handlers::app_routes, services::auth::AuthService, services::otp::OtpService, state::AppState,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("auth67=info".parse().unwrap())
                .add_directive("tower_http=debug".parse().unwrap()),
        )
        .init();

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .connect(&CONFIG.database.url)
        .await?;

    let crypto = Arc::new(CryptoAdapter::new(CONFIG.crypto.secret.clone()));

    let auth = Arc::new(AuthService::new(
        CONFIG.auth.clone(),
        pool.clone(),
        crypto.clone(),
        CONFIG.auth.private_key_pem(),
        CONFIG.auth.public_key_pem(),
        &CONFIG.auth.audience,
        &CONFIG.auth.issuer,
    )?);

    let comms = Arc::new(CommsAdapter::new(
        CONFIG.comms.username.clone(),
        CONFIG.comms.password.clone(),
        CONFIG.comms.resend_api_key.clone(),
    ));

    let otp = Arc::new(OtpService::new(
        CONFIG.otp.clone(),
        CONFIG.comms.clone(),
        pool.clone(),
        comms,
        crypto.clone(),
    ));

    let app_state = Arc::new(AppState::new(pool, auth, otp));
    app_state.spawn_otp_cron_job();
    app_state.spawn_audit_cron_job();

    let app = app_routes(app_state);
    let addr = format!("{}:{}", CONFIG.server.address, CONFIG.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    info!("Server running on http://{}", addr);

    axum::serve(listener, app).await.unwrap();
    Ok(())
}
