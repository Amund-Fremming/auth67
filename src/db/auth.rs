use chrono::{DateTime, Utc};
use sqlx::{Executor, Pool, Postgres};
use uuid::Uuid;

use crate::error::ServerError;
use crate::models::auth::{
    LoginCredentials, ProviderType, Session, SessionDto, UserCredential, UserIdentity,
};

pub async fn create_identity<'e, E>(
    exec: E,
    user_id: Uuid,
    provider_type: ProviderType,
    identifier: &str, // email or phone_number
) -> Result<UserIdentity, ServerError>
where
    E: Executor<'e, Database = Postgres>,
{
    let identity = sqlx::query_as!(
        UserIdentity,
        r#"
        INSERT INTO user_identity (id, user_id, provider_type, identifier)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, provider_type as "provider_type: ProviderType", identifier, created_at
        "#,
        Uuid::new_v4(),
        user_id,
        provider_type as ProviderType,
        identifier
    )
    .fetch_one(exec)
    .await?;

    Ok(identity)
}

/// Checks `user_identity`, the authoritative table for login identifiers.
/// The `user` table's phone/email columns are denormalized copies written
/// in the same transaction, so they never need a separate check.
pub async fn is_identifier_in_use(
    pool: &Pool<Postgres>,
    provider_type: ProviderType,
    identifier: &str,
) -> Result<bool, ServerError> {
    let exists = sqlx::query_scalar!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM user_identity
            WHERE provider_type = $1 AND identifier = $2
        ) as "exists!"
        "#,
        provider_type as ProviderType,
        identifier
    )
    .fetch_one(pool)
    .await?;

    Ok(exists)
}

pub async fn get_credential(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    provider_type: &ProviderType,
) -> Result<Option<UserCredential>, ServerError> {
    let credential = sqlx::query_as!(
        UserCredential,
        r#"
        SELECT uc.id, uc.identity_id, uc.password_hash, uc.failed_attempts, uc.locked_until, uc.created_at, uc.updated_at
        FROM user_credential uc
        INNER JOIN user_identity ui ON uc.identity_id = ui.id
        WHERE ui.user_id = $1 AND ui.provider_type = $2
        "#,
        user_id,
        *provider_type as ProviderType
    )
    .fetch_optional(pool)
    .await?;

    Ok(credential)
}

pub async fn create_credential<'e, E>(
    exec: E,
    identity_id: Uuid,
    password_hash: &str,
) -> Result<UserCredential, ServerError>
where
    E: Executor<'e, Database = Postgres>,
{
    let credential = sqlx::query_as!(
        UserCredential,
        r#"
        INSERT INTO user_credential (id, identity_id, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id, identity_id, password_hash, failed_attempts, locked_until, created_at, updated_at
        "#,
        Uuid::new_v4(),
        identity_id,
        password_hash
    )
    .fetch_one(exec)
    .await?;

    Ok(credential)
}

pub async fn set_credential_password(
    pool: &Pool<Postgres>,
    credential_id: Uuid,
    password_hash: &str,
) -> Result<(), ServerError> {
    sqlx::query!(
        r#"
        UPDATE user_credential
        SET password_hash = $1, updated_at = NOW()
        WHERE id = $2
        "#,
        password_hash,
        credential_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_login_credentials(
    pool: &Pool<Postgres>,
    identifier: &str,
    provider_type: ProviderType,
) -> Result<Option<LoginCredentials>, ServerError> {
    let option = sqlx::query!(
        r#"
        SELECT ui.id as identity_id, ui.user_id, uc.password_hash, uc.failed_attempts, uc.locked_until
        FROM user_credential uc
        INNER JOIN user_identity ui ON ui.id = uc.identity_id
        WHERE ui.provider_type = $1 AND ui.identifier = $2
        "#,
        provider_type as ProviderType,
        identifier,
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = option else { return Ok(None) };
    let login_object = LoginCredentials {
        user_id: row.user_id,
        identity_id: row.identity_id,
        password_hash: row.password_hash,
        locked_until: row.locked_until,
        failed_attempts: row.failed_attempts,
    };

    Ok(Some(login_object))
}

/// Atomically increments failed_attempts and returns the new count.
pub async fn increment_and_get_failed_attempts(
    pool: &Pool<Postgres>,
    identity_id: Uuid,
) -> Result<i32, ServerError> {
    let new_count = sqlx::query_scalar!(
        r#"
        UPDATE user_credential
        SET failed_attempts = failed_attempts + 1, updated_at = NOW()
        WHERE identity_id = $1
        RETURNING failed_attempts
        "#,
        identity_id
    )
    .fetch_one(pool)
    .await?;

    Ok(new_count)
}

pub async fn reset_failed_attempts(
    pool: &Pool<Postgres>,
    identity_id: Uuid,
) -> Result<(), ServerError> {
    sqlx::query!(
        r#"
        UPDATE user_credential
        SET failed_attempts = 0, locked_until = NULL, updated_at = NOW()
        WHERE identity_id = $1
        "#,
        identity_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn lock_account(
    pool: &Pool<Postgres>,
    identity_id: Uuid,
    lock_hours: i64,
) -> Result<(), ServerError> {
    sqlx::query!(
        r#"
        UPDATE user_credential
        SET locked_until = NOW() + ($2 || ' hours')::interval, updated_at = NOW()
        WHERE identity_id = $1
        "#,
        identity_id,
        lock_hours.to_string()
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn create_session<'e, E>(
    exec: E,
    user_id: Uuid,
    device_id: Uuid,
    device_name: &str,
    refresh_token_hash: &str,
    expires_at: DateTime<Utc>,
    user_agent: Option<&str>,
) -> Result<Session, ServerError>
where
    E: Executor<'e, Database = Postgres>,
{
    let session = sqlx::query_as!(
        Session,
        r#"
        INSERT INTO session (device_id, user_id, refresh_token_hash, expires_at, user_agent, device_name)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING device_id, user_id, refresh_token_hash, user_agent, device_name, expires_at, revoked_at, created_at, last_used_at
        "#,
        device_id,
        user_id,
        refresh_token_hash,
        expires_at,
        user_agent,
        device_name
    )
    .fetch_one(exec)
    .await?;

    Ok(session)
}

pub async fn upsert_session<'e, E>(
    exec: E,
    user_id: Uuid,
    device_id: Uuid,
    device_name: &str,
    refresh_token_hash: &str,
    expires_at: DateTime<Utc>,
    user_agent: Option<&str>,
) -> Result<Session, ServerError>
where
    E: Executor<'e, Database = Postgres>,
{
    let session = sqlx::query_as!(
        Session,
        r#"
        INSERT INTO session (device_id, user_id, refresh_token_hash, expires_at, user_agent, device_name)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (device_id) DO UPDATE SET
            refresh_token_hash = EXCLUDED.refresh_token_hash,
            expires_at = EXCLUDED.expires_at,
            user_agent = EXCLUDED.user_agent,
            device_name = EXCLUDED.device_name,
            revoked_at = NULL,
            last_used_at = NOW()
        RETURNING device_id, user_id, refresh_token_hash, user_agent, device_name, expires_at, revoked_at, created_at, last_used_at
        "#,
        device_id,
        user_id,
        refresh_token_hash,
        expires_at,
        user_agent,
        device_name
    )
    .fetch_one(exec)
    .await?;

    Ok(session)
}

pub async fn get_session(
    pool: &Pool<Postgres>,
    device_id: Uuid,
) -> Result<Option<Session>, ServerError> {
    let session = sqlx::query_as!(
        Session,
        r#"
        SELECT device_id, user_id, refresh_token_hash, user_agent, device_name, expires_at, revoked_at, created_at, last_used_at
        FROM session
        WHERE device_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
        "#,
        device_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(session)
}

pub async fn expire_session(pool: &Pool<Postgres>, device_id: Uuid) -> Result<(), ServerError> {
    sqlx::query!(
        r#"
        UPDATE session
        SET revoked_at = NOW()
        WHERE device_id = $1
        "#,
        device_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn list_session_dtos(
    pool: &Pool<Postgres>,
    user_id: Uuid,
) -> Result<Vec<SessionDto>, ServerError> {
    let sessions = sqlx::query_as!(
        SessionDto,
        r#"
        SELECT device_id, device_name, user_agent, (revoked_at IS NULL AND expires_at > NOW()) as "active!"
        FROM session
        WHERE user_id = $1
        ORDER BY last_used_at DESC NULLS LAST
        "#,
        user_id
    )
    .fetch_all(pool)
    .await?;

    Ok(sessions)
}

pub async fn update_session(
    pool: &Pool<Postgres>,
    device_id: Uuid,
    new_token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), ServerError> {
    sqlx::query!(
        r#"
        UPDATE session
        SET refresh_token_hash = $1, expires_at = $2, last_used_at = NOW()
        WHERE device_id = $3
        "#,
        new_token_hash,
        expires_at,
        device_id
    )
    .execute(pool)
    .await?;

    Ok(())
}
