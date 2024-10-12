use axum::response::IntoResponse;
use redis::{AsyncCommands, Client, RedisError};
use reqwest::StatusCode;

#[derive(Debug)]
pub enum CacheError {
    Redis(RedisError),
    FormatError(serde_json::Error),
}

impl IntoResponse for CacheError {
    fn into_response(self) -> axum::response::Response {
        match self {
            CacheError::Redis(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Redis connection error").into_response()
            }
            CacheError::FormatError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Invalid data format").into_response()
            }
        }
    }
}

#[async_trait::async_trait]
pub trait TCache: Clone + Sync + Send {
    async fn get(&self, key: &str) -> Result<Option<String>, CacheError>;
    async fn delete(&self, key: &str) -> Result<(), CacheError>;
    async fn set(&self, key: &str, value: &str) -> Result<(), CacheError>;
}

#[derive(Clone)]
pub struct RedisCache {
    redis_client: Client,
}

impl RedisCache {
    pub fn try_new(uri: &str) -> Result<Self, CacheError> {
        Ok(Self {
            redis_client: Client::open(uri).map_err(CacheError::Redis)?,
        })
    }
}

#[async_trait::async_trait]
impl TCache for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<String>, CacheError> {
        let mut connection = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(CacheError::Redis)?;

        let result = connection
            .get::<String, Option<String>>(key.to_string())
            .await
            .map_err(CacheError::Redis)?;

        if result.is_none() {
            return Ok(None);
        }

        Ok(Some(result.unwrap()))
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        let mut connection = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(CacheError::Redis)?;

        connection
            .del::<&String, i64>(&key.to_string())
            .await
            .map_err(CacheError::Redis)?;

        Ok(())
    }

    async fn set(&self, key: &str, value: &str) -> Result<(), CacheError> {
        let mut connection = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(CacheError::Redis)?;

        connection
            .set::<&str, &str, String>(key, value)
            .await
            .map_err(CacheError::Redis)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisCacheState {
    pub cache: RedisCache
}