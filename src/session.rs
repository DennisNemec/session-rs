use std::fmt::Display;

use axum::{
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use bson::Uuid;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cache::TCache;

pub mod builder;
pub mod service;

#[derive(Debug)]
pub enum SessionError {
    Unregistered,
    InvalidIdToken,
    NoIdCookie,
    SessionStoreError,
}

impl IntoResponse for SessionError {
    fn into_response(self) -> axum::response::Response {
        match self {
            SessionError::Unregistered => {
                (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
            }
            SessionError::NoIdCookie => (StatusCode::BAD_REQUEST, "No id cookie").into_response(),
            SessionError::InvalidIdToken => {
                (StatusCode::BAD_REQUEST, "Invalid ID token").into_response()
            }
            SessionError::SessionStoreError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Session store issues").into_response()
            }
        }
    }
}

impl Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("session error")
    }
}

impl std::error::Error for SessionError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub session_id: Uuid,
    pub user_id: Option<String>,
    pub access_token: String,
    pub id_token: String,
}

#[async_trait::async_trait]
pub trait TSessionStore: Clone + Sync + Send {
    async fn get(&self, session_id: &str) -> Result<Option<Session>, SessionError>;
    async fn set(&self, session: &Session) -> Result<(), SessionError>;
}

pub trait TAuthorizationStore {
    fn get(&self, user_id: &str, external_id: bool) -> Result<Value, SessionError>;
}

#[derive(Clone)]
pub struct CachedSessionStore<C: TCache, S: TSessionStore> {
    cache: C,
    store: S,
}

impl<C: TCache, S: TSessionStore> CachedSessionStore<C, S> {
    pub fn new(cache: C, store: S) -> Self {
        Self { cache, store }
    }

    fn get_key(&self, id: &str) -> String {
        format!("session:{id}")
    }
}

#[async_trait::async_trait]
impl<C: TCache, S: TSessionStore + Sync> TSessionStore for CachedSessionStore<C, S> {
    async fn get(&self, session_id: &str) -> Result<Option<Session>, SessionError> {
        let cache_result = self
            .cache
            .get(self.get_key(session_id).as_str())
            .await
            .map_err(|_| SessionError::SessionStoreError)?;

        // Return the session that is already present in cache
        if let Some(session) = cache_result {
            return Ok(Some(
                serde_json::from_str::<Session>(&session)
                    .map_err(|_| SessionError::SessionStoreError)?,
            ));
        }

        // Session not present in cache, so check the session service
        let session_opt = self.store.get(session_id).await?;

        if session_opt.is_none() {
            return Ok(None);
        }

        let session = session_opt.unwrap();

        // Store session in cache
        let session_response_str =
            serde_json::to_string(&session).map_err(|_| SessionError::SessionStoreError)?;
        self.cache
            .set(self.get_key(session_id).as_str(), &session_response_str)
            .await
            .map_err(|_| SessionError::SessionStoreError)?;

        Ok(Some(session))
    }

    async fn set(&self, session: &Session) -> Result<(), SessionError> {
        self.cache
            .set(
                self.get_key(&session.session_id.to_string()).as_str(),
                serde_json::to_string(&session)
                    .map_err(|_| SessionError::SessionStoreError)?
                    .as_str(),
            )
            .await
            .map_err(|_| SessionError::SessionStoreError)?;

        self.store.set(session).await?;

        Ok(())
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct SessionStore {
    endpoint_url: String,
}

impl SessionStore {
    pub fn new(url: &str) -> Self {
        Self {
            endpoint_url: url.to_string(),
        }
    }

    fn get_url(&self, session_id: &str) -> String {
        format!("{}/{session_id}", self.endpoint_url)
    }
}

#[async_trait::async_trait]
impl TSessionStore for SessionStore {
    async fn get(&self, session_id: &str) -> Result<Option<Session>, SessionError> {
        // Session not present in cache, so check the session service
        let session_response = reqwest::get(self.get_url(session_id).as_str())
            .await
            .map_err(|_| SessionError::SessionStoreError)?;

        // Session does not exist
        if session_response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let session_response_str = session_response
            .text()
            .await
            .map_err(|_| SessionError::SessionStoreError)?;
        let session = serde_json::from_str::<Session>(&session_response_str)
            .map_err(|_| SessionError::SessionStoreError)?;

        Ok(Some(session))
    }

    async fn set(&self, session: &Session) -> Result<(), SessionError> {
        let payload_str = serde_json::to_string(&session).unwrap();
        let client = reqwest::Client::new();
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Type",
            HeaderValue::from_str("application/json").unwrap(),
        );

        let request = client
            .post(&self.endpoint_url)
            .body(payload_str)
            .headers(headers)
            .send()
            .await
            .map_err(|_| SessionError::SessionStoreError)?;

        if request.status() == StatusCode::OK {
            Ok(())
        } else {
            Err(SessionError::SessionStoreError)
        }
    }
}
