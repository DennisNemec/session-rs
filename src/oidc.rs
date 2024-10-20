pub mod controller;
pub mod service;

use axum::response::IntoResponse;
use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod, CoreGrantType,
    CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
    CoreSubjectIdentifierType,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AdditionalProviderMetadata, AuthenticationFlow, IssuerUrl, Nonce, ProviderMetadata,
    RevocationUrl,
};
use openidconnect::{AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug)]
pub enum OidcError {
    OAuthError,
    Unauthorized,
    CsrfTokenMismatch,
    OidcDiscoveryError,
    AuthSessionMissing,
    ExchangeCodeError,
    IdTokenMissing,
    IdTokenVerificationInvalid,
}

impl Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OidcError::Unauthorized => f.pad(""),
            OidcError::IdTokenVerificationInvalid => {
                f.pad("The signature of the ID token seems to be corrupt")
            }
            OidcError::IdTokenMissing => f.pad("No ID token received from OIDC provider"),
            OidcError::ExchangeCodeError => f.pad("Error while exchanging OIDC code"),
            OidcError::AuthSessionMissing => f.pad("No authentication session is set"),
            OidcError::OidcDiscoveryError => f.pad("Error during OIDC provider discovery"),
            OidcError::OAuthError => f.pad("OAuth authorization failed"),
            OidcError::CsrfTokenMismatch => f.pad("CSRF token do not match"),
        }
    }
}

impl std::error::Error for OidcError {}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UserSession {
    pub id_token: String,
}

impl IntoResponse for OidcError {
    fn into_response(self) -> axum::response::Response {
        match self {
            OidcError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            OidcError::IdTokenVerificationInvalid => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "The signature of the ID token seems to be corrupt",
            )
                .into_response(),
            OidcError::IdTokenMissing => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "No ID token received from OIDC provider",
            )
                .into_response(),
            OidcError::ExchangeCodeError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error while exchanging OIDC code",
            )
                .into_response(),
            OidcError::AuthSessionMissing => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "No authentication session is set",
            )
                .into_response(),
            OidcError::OidcDiscoveryError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error during OIDC provider discovery",
            )
                .into_response(),
            OidcError::OAuthError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "OAuth authorization failed",
            )
                .into_response(),
            OidcError::CsrfTokenMismatch => {
                (StatusCode::BAD_REQUEST, "CSRF token do not match").into_response()
            }
        }
    }
}

#[derive(Clone)]
pub struct OidcState {
    pub client: CoreClient,
    pub callback_url: String,
    pub login_url: String,
    pub logout_url: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct OidcConfiguration {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub callback_path: String,
    pub login_path: String,
    pub logout_path: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OidcSecurityInformation {
    pub old_csrf: CsrfToken,
    pub nonce: Nonce,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<AuthorizationCode>,
    pub state: CsrfToken,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RevocationEndpointProviderMetadata {
    revocation_endpoint: String,
}
impl AdditionalProviderMetadata for RevocationEndpointProviderMetadata {}
type CustomProviderMetadata = ProviderMetadata<
    RevocationEndpointProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

impl OidcState {
    pub async fn new(
        issuer_url: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        callback_url: &str,
        login_url: &str,
        logout_url: &str,
    ) -> Result<Self, OidcError> {
        let provider_metadata = CustomProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url.to_string()).unwrap(),
            async_http_client,
        )
        .await
        .map_err(|_| OidcError::OidcDiscoveryError)?;

        let revocation_url = provider_metadata
            .additional_metadata()
            .revocation_endpoint
            .clone();

        Ok(Self {
            logout_url: logout_url.to_string(),
            callback_url: callback_url.to_string(),
            login_url: login_url.to_string(),
            client: CoreClient::from_provider_metadata(
                provider_metadata,
                ClientId::new(client_id.to_string()),
                Some(ClientSecret::new(client_secret.to_string())),
            )
            .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).unwrap())
            .set_revocation_uri(RevocationUrl::new(revocation_url).unwrap()),
        })
    }

    pub fn authorize_url(&self) -> (Url, CsrfToken, Nonce) {
        self.client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url()
    }
}

pub const SESSION_KEY: &str = "id";
