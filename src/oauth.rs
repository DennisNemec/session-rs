pub mod routes;
pub mod controller;

use oauth2::CsrfToken;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{app::AppError};

#[derive(Clone)]
pub struct OAuth {
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    redirect_url: String,
    scopes: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthCredentials {
    pub code: String,
    pub token_old: CsrfToken,
    pub token_new: CsrfToken
}

impl OAuth {
    pub fn new(
        client_id: String,
        client_secret: String,
        auth_url: String,
        token_url: String,
        redirect_url: String,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            auth_url,
            token_url,
            redirect_url,
            scopes,
        }
    }
}