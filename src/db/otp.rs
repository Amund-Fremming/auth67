use std::time::Duration;

use chrono::Utc;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::error::{AppErrorCode, ServerError};
use crate::models::{
    auth::ProviderType,
    otp::{Otp, OtpResponse},
};

pub async fn get_otp_by_id(pool: &Pool<Postgres>, id: Uuid) -> Result<Otp, ServerError> {
    let otp = sqlx::query_as!(
        Otp,
        r#"
        SELECT id, identifier, provider_type as "provider_type: ProviderType", hash, expires_at, verified_at, created_at, ip_address, failed_attempts
        FROM "otp"
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await?;

    match otp {
        Some(otp) => Ok(otp),
        None => Err(ServerError::App(
            AppErrorCode::OtpNotFound,
            "OTP not found".to_string(),
        )),
    }
}

pub async fn get_otp_by_identifier(
    pool: &Pool<Postgres>,
    identifier: &str,
    provider_type: ProviderType,
) -> Result<Otp, ServerError> {
    let otp = sqlx::query_as!(
        Otp,
        r#"
        SELECT id, identifier, provider_type as "provider_type: ProviderType", hash, expires_at, verified_at, created_at, ip_address, failed_attempts
        FROM "otp"
        WHERE identifier = $1 AND provider_type = $2
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        identifier,
        provider_type as ProviderType
    )
    .fetch_optional(pool)
    .await?;

    match otp {
        Some(otp) => Ok(otp),
        None => Err(ServerError::App(
            AppErrorCode::OtpNotFound,
            "OTP not found".to_string(),
        )),
    }
}

/// Atomically increments failed_attempts and returns the new count.
pub async fn increment_and_get_failed_attempts(
    pool: &Pool<Postgres>,
    otp_id: Uuid,
) -> Result<i32, sqlx::Error> {
    let new_count = sqlx::query_scalar!(
        r#"
        UPDATE "otp"
        SET failed_attempts = failed_attempts + 1
        WHERE id = $1
        RETURNING failed_attempts
        "#,
        otp_id
    )
    .fetch_one(pool)
    .await?;

    Ok(new_count)
}

pub async fn mark_verified(pool: &Pool<Postgres>, otp_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE "otp"
        SET verified_at = NOW()
        WHERE id = $1
        "#,
        otp_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_expired_otps(pool: &Pool<Postgres>) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        DELETE FROM "otp"
        WHERE expires_at < NOW()
        "#
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

async fn get_otp_count_today(
    pool: &Pool<Postgres>,
    identifier: &str,
    provider_type: ProviderType,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM "otp"
        WHERE identifier = $1 AND provider_type = $2 AND created_at >= CURRENT_DATE
        "#,
        identifier,
        provider_type as ProviderType
    )
    .fetch_one(pool)
    .await
}

pub async fn create_otp(
    pool: &Pool<Postgres>,
    identifier: &str,
    provider_type: ProviderType,
    hash: &str,
    ttl_minutes: u8,
    max_messages_per_day: i64,
) -> Result<OtpResponse, ServerError> {
    let expires_at = Utc::now() + Duration::from_mins(ttl_minutes as u64);

    let otp_today = get_otp_count_today(pool, identifier, provider_type).await?;
    if otp_today >= max_messages_per_day {
        return Err(ServerError::App(
            AppErrorCode::OtpMaxMessages,
            "Max messages per day exceeded".to_string(),
        ));
    }

    let otp_id = sqlx::query_scalar!(
        r#"
        INSERT INTO "otp" (identifier, provider_type, hash, expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
        identifier,
        provider_type as ProviderType,
        hash,
        expires_at
    )
    .fetch_one(pool)
    .await?;

    let response = OtpResponse { otp_id };
    Ok(response)
}

pub async fn delete_otp(pool: &Pool<Postgres>, otp_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        DELETE FROM "otp"
        WHERE id = $1
        "#,
        otp_id
    )
    .execute(pool)
    .await?;

    Ok(())
}
