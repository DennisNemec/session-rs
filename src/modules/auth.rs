use std::fmt::Debug;

use axum::response::IntoResponse;
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Serialize};

use crate::cache::CacheError;

pub mod oauth;
pub mod session;
pub mod claims;

const CSRF_OLD_KEY: &str = "CSRF_OLD";

#[derive(Debug)]
pub enum AuthError {
    Tokio(std::io::Error),
    Json(serde_json::Error),
    HttpError(reqwest::Error),
    CacheError(CacheError),
    OAuthError,
    InvalidCsrfToken,
    InvalidCookie,
    Unauthorized,
    Forbidden,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AuthError::Tokio(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Tokio error").into_response(),
            AuthError::Json(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Invalid format").into_response(),
            AuthError::HttpError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "HTTP error").into_response(),
            AuthError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            AuthError::Forbidden => StatusCode::FORBIDDEN.into_response(),
            AuthError::CacheError(cache) => cache.into_response(),
            AuthError::InvalidCookie => (StatusCode::BAD_REQUEST, "Invalid session cookie").into_response(),
            AuthError::InvalidCsrfToken => (StatusCode::BAD_REQUEST, "Invalid CSRF token").into_response(),
            AuthError::OAuthError => (StatusCode::INTERNAL_SERVER_ERROR, "OAuth authorization failed").into_response(),
        }
    }
}

pub trait TPerson: Serialize + DeserializeOwned + Sync + Send + Debug + Clone {
    fn get_mail(&self) -> String;
    fn get_first_name(&self) -> String;
    fn get_last_name(&self) -> String;
}