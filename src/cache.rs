use std::fmt::{Debug, Display};

use crate::{
    app::AppError,
    session::{Session, TSession},
};
use redis::{AsyncCommands, Client};
use serde::{de::DeserializeOwned, Serialize};

#[async_trait::async_trait]
pub trait TCache {
    type Error: Display + Debug;
    type Session: DeserializeOwned + Serialize + Debug + TSession + Send + Sync;

    async fn get(&self, key: &String) -> Result<Option<Self::Session>, Self::Error>;
    async fn delete(&self, key: &String) -> Result<(), Self::Error>;
    async fn set(
        &self,
        key: &String,
        session: impl DeserializeOwned + Serialize + Send + Sync,
    ) -> Result<(), Self::Error>;
}

#[derive(Clone)]
pub struct RedisCache {
    redis_client: Client,
}

impl RedisCache {
    pub fn try_new(uri: &str) -> Result<Self, AppError> {
        Ok(Self {
            redis_client: Client::open(uri).map_err(AppError::Redis)?,
        })
    }
}

#[async_trait::async_trait]
impl TCache for RedisCache {
    type Error = AppError;
    type Session = Session;

    async fn get(&self, key: &String) -> Result<Option<Self::Session>, Self::Error> {
        let mut connection = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(Self::Error::Redis)?;

        let result = connection
            .get::<String, Option<String>>(key.to_string())
            .await
            .map_err(Self::Error::Redis)?;

        if let None = result {
            return Ok(None);
        }

        Ok(Some(
            serde_json::from_str::<Self::Session>(result.unwrap().as_str())
                .map_err(Self::Error::Json)?,
        ))
    }

    async fn delete(&self, key: &String) -> Result<(), Self::Error> {
        let mut connection = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(Self::Error::Redis)?;

        let result = connection
            .del::<&String, i64>(key)
            .await
            .map_err(Self::Error::Redis)?;

        println!("RESULT {result}");

        Ok(())
    }

    async fn set(
        &self,
        key: &String,
        session: impl DeserializeOwned + Serialize + Send + Sync,
    ) -> Result<(), Self::Error> {
        let mut connection = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(Self::Error::Redis)?;

        connection
            .set::<&String, String, String>(
                key,
                serde_json::to_string(&session).map_err(Self::Error::Json)?,
            )
            .await
            .map_err(Self::Error::Redis)?;

        Ok(())
    }
}
