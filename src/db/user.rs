use sqlx::{Executor, Pool, Postgres};
use tracing::warn;
use uuid::Uuid;

use crate::db;
use crate::error::ServerError;
use crate::models::user::{PatchUserRequest, User};

pub async fn get_user(pool: &Pool<Postgres>, id: Uuid) -> Result<Option<User>, ServerError> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT id, phone_number, phone_number_verified, email, email_verified, given_name, family_name, avatar_url, created_at, updated_at, last_active_at
        FROM "user"
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn list_users(
    pool: &Pool<Postgres>,
    limit: i32,
    offset: i32,
) -> Result<Vec<User>, ServerError> {
    let users = sqlx::query_as!(
        User,
        r#"
        SELECT id, phone_number, phone_number_verified, email, email_verified, given_name, family_name, avatar_url, created_at, updated_at, last_active_at
        FROM "user"
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
        limit as i64,
        offset as i64
    )
    .fetch_all(pool)
    .await?;

    Ok(users)
}

pub async fn create_user<'e, E>(exec: E, user: &User) -> Result<User, ServerError>
where
    E: Executor<'e, Database = Postgres>,
{
    let created = sqlx::query_as!(
        User,
        r#"
        INSERT INTO "user" (id, phone_number, phone_number_verified, email, email_verified, given_name, family_name)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, phone_number, phone_number_verified, email, email_verified, given_name, family_name, avatar_url, created_at, updated_at, last_active_at
        "#,
        user.id,
        user.phone_number,
        user.phone_number_verified,
        user.email,
        user.email_verified,
        user.given_name,
        user.family_name
    )
    .fetch_one(exec)
    .await?;

    Ok(created)
}

pub async fn patch_user(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    req: &PatchUserRequest,
) -> Result<User, ServerError> {
    if req.given_name.is_none() && req.family_name.is_none() && req.avatar_url.is_none() {
        warn!("User tried patching with no updated fields");
        return db::user::get_user(pool, user_id)
            .await?
            .ok_or(ServerError::NotFound);
    }

    let user = sqlx::query_as!(
        User,
        r#"
        UPDATE "user"
        SET
            given_name = COALESCE($2, given_name),
            family_name = COALESCE($3, family_name),
            avatar_url = COALESCE($4, avatar_url),
            updated_at = NOW()
        WHERE id = $1
        RETURNING id, phone_number, phone_number_verified, email, email_verified, given_name, family_name, avatar_url, created_at, updated_at, last_active_at
        "#,
        user_id,
        req.given_name.as_deref(),
        req.family_name.as_deref(),
        req.avatar_url.as_deref()
    )
    .fetch_optional(pool)
    .await?
    .ok_or(ServerError::NotFound)?;

    Ok(user)
}

pub async fn delete_user(pool: &Pool<Postgres>, id: Uuid) -> Result<bool, ServerError> {
    let result = sqlx::query!(
        r#"
        DELETE FROM "user"
        WHERE id = $1
        "#,
        id
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn touch_last_active(pool: &Pool<Postgres>, user_id: Uuid) -> Result<(), ServerError> {
    sqlx::query!(
        r#"
        UPDATE "user"
        SET last_active_at = NOW()
        WHERE id = $1
        "#,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}
