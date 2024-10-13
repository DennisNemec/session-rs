use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use bson::Uuid;
use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod, CoreGrantType,
    CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
    CoreSubjectIdentifierType,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AdditionalProviderMetadata, AuthenticationFlow, IssuerUrl, Nonce, OAuth2TokenResponse, ProviderMetadata, RevocationUrl
};
use openidconnect::{AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

use crate::cache::TCache;
use crate::session::{Session, TSessionStore};

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
pub struct OidcConfiguration {
    pub client: CoreClient,
    pub callback_url: String,
    pub login_url: String,
    pub logout_url: String,
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

impl OidcConfiguration {
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

pub async fn handle_login_request<Cache: TCache>(
    auth: &OidcConfiguration,
    jar: &CookieJar,
    cache: &Cache,
) -> Result<impl IntoResponse, OidcError> {
    let (auth_url, old_token, nonce) = auth.authorize_url();

    let authentification_session = OidcSecurityInformation {
        old_csrf: old_token,
        nonce,
    };

    let session_id = if let Some(e) = jar.get(SESSION_KEY) {
        e.to_owned()
    } else {
        Cookie::new(SESSION_KEY, Uuid::new().to_string())
    };

    cache
        .set(
            format!("auth:{}", session_id.value()).as_str(),
            serde_json::to_string(&authentification_session)
                .unwrap()
                .as_str(),
        )
        .await
        .map_err(|_| OidcError::OAuthError)?;

    Ok((jar.clone().add(session_id), Redirect::to(auth_url.as_str())))
}

pub async fn handle_oauth_callback<Cache: TCache, S: TSessionStore>(
    jar: &CookieJar,
    code: AuthorizationCode,
    csrf_token: CsrfToken,
    auth: &OidcConfiguration,
    cache: &Cache,
    store: &S
) -> Result<impl IntoResponse, OidcError> {
    let session_key = if let Some(s) = jar.get(SESSION_KEY).map(|c| c.value()) {
        s
    } else {
        return Err(OidcError::AuthSessionMissing);
    };

    let auth_session = if let Some(serialized_auth_session) = cache
        .get(format!("auth:{session_key}").as_str())
        .await
        .map_err(|_| OidcError::OAuthError)?
    {
        serde_json::from_str::<OidcSecurityInformation>(&serialized_auth_session).unwrap()
    } else {
        return Err(OidcError::AuthSessionMissing);
    };

    if *auth_session.old_csrf.secret() != *csrf_token.secret() {
        return Err(OidcError::CsrfTokenMismatch);
    }

    let token = auth
        .client
        .exchange_code(code)
        .request_async(async_http_client)
        .await
        .map_err(|_| OidcError::ExchangeCodeError)?;

    let identifier = auth.client.id_token_verifier();
    let id_token = token.extra_fields().id_token();
    if id_token.is_none() {
        return Err(OidcError::IdTokenMissing);
    }

    id_token
        .unwrap()
        .claims(&identifier, &auth_session.nonce)
        .map_err(|_| OidcError::IdTokenVerificationInvalid)?;
    
    let session = Session {
        session_id: Uuid::parse_str(session_key).unwrap(),
        user_id: None,
        access_token: token.access_token().secret().to_string(),
        id_token: id_token.unwrap().to_string(),
    };

    store.set(&session).await.map_err(|_| OidcError::OAuthError)?;

    Ok(Redirect::to("/"))
}
