use axum::extract::{Query, Request, State};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use bson::Uuid;
use openidconnect::core::{CoreClient, CoreResponseType};
use openidconnect::reqwest::async_http_client;
use openidconnect::{core::CoreProviderMetadata, IssuerUrl};
use openidconnect::{AuthenticationFlow, Nonce};
use openidconnect::{AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};

use crate::cache::TCache;

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
pub struct OidcConfiguration<Cache: TCache + Clone + Sync + Send> {
    pub client: CoreClient,
    pub callback_url: String,
    pub login_url: String,
    pub cache: Cache,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OidcExchangeSession {
    pub old_csrf: CsrfToken,
    pub nonce: Nonce,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthCallbackQuery {
    code: AuthorizationCode,
    state: CsrfToken,
}

impl<Cache: TCache + Clone + Sync + Send> OidcConfiguration<Cache> {
    pub async fn new(
        issuer_url: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        callback_url: &str,
        login_url: &str,
        cache: Cache,
    ) -> Result<Self, OidcError> {
        Ok(Self {
            callback_url: callback_url.to_string(),
            cache,
            login_url: login_url.to_string(),
            client: CoreClient::from_provider_metadata(
                CoreProviderMetadata::discover_async(
                    IssuerUrl::new(issuer_url.to_string()).unwrap(),
                    async_http_client,
                )
                .await
                .map_err(|_| OidcError::OidcDiscoveryError)?,
                ClientId::new(client_id.to_string()),
                Some(ClientSecret::new(client_secret.to_string())),
            )
            .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).unwrap()),
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

const SESSION_KEY: &str = "id";

pub async fn oidc_auth<Cache: TCache + Clone + Sync + Send>(
    jar: CookieJar,
    State(auth): State<OidcConfiguration<Cache>>,
    mut request: Request,
    next: Next,
) -> Result<Response, OidcError> {
    fn add_session_header(request: &mut Request, session: String) {
        let mutable_header = request.headers_mut();

        mutable_header.insert(
            "Authorization",
            HeaderValue::from_str(format!("Bearer {}", session).as_str()).unwrap(),
        );
    }

    let session_key = jar.get(SESSION_KEY).map(|c| c.value());

    if let Some(s) = session_key {
        if let Some(serialized_session) = auth
            .cache
            .get(format!("claim:{s}").as_str())
            .await
            .map_err(|_| OidcError::OAuthError)?
        {
            let session = serde_json::from_str::<UserSession>(&serialized_session).unwrap();
            add_session_header(&mut request, session.id_token);
            return Ok(next.run(request).await);
        }
    }

    let path = Some(request.uri().path().to_string());
    if let Some(v) = path {
        if v == auth.login_url {
            return Ok(handle_login_request(&auth, &jar).await?.into_response());
        } else if v == auth.callback_url {
            let Query(OAuthCallbackQuery { code, state }) =
                Query::try_from_uri(request.uri()).unwrap();

            return Ok(handle_oauth_callback(&jar, code, state, &auth)
                .await?
                .into_response());
        } else {
            return Ok(Redirect::to(&auth.login_url).into_response());
        }
    }

    Ok(next.run(request).await)
}

pub async fn handle_login_request<Cache: TCache + Clone + Sync + Send>(
    auth: &OidcConfiguration<Cache>,
    jar: &CookieJar,
) -> Result<impl IntoResponse, OidcError> {
    let (auth_url, old_token, nonce) = auth.authorize_url();

    let authentification_session = OidcExchangeSession {
        old_csrf: old_token,
        nonce,
    };

    let session_id = if let Some(e) = jar.get(SESSION_KEY) {
        e.to_owned()
    } else {
        Cookie::new(SESSION_KEY, Uuid::new().to_string())
    };

    auth.cache
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

pub async fn handle_oauth_callback<Cache: TCache + Clone + Sync + Send>(
    jar: &CookieJar,
    code: AuthorizationCode,
    csrf_token: CsrfToken,
    auth: &OidcConfiguration<Cache>,
) -> Result<impl IntoResponse, OidcError> {
    let session_key = if let Some(s) = jar.get(SESSION_KEY).map(|c| c.value()) {
        s
    } else {
        return Err(OidcError::AuthSessionMissing);
    };

    let auth_session = if let Some(serialized_auth_session) = auth
        .cache
        .get(format!("auth:{session_key}").as_str())
        .await
        .map_err(|_| OidcError::OAuthError)?
    {
        serde_json::from_str::<OidcExchangeSession>(&serialized_auth_session).unwrap()
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
    if let None = id_token {
        return Err(OidcError::IdTokenMissing);
    }

    id_token
        .unwrap()
        .claims(&identifier, &auth_session.nonce)
        .map_err(|_| OidcError::IdTokenVerificationInvalid)?;

    let user_session = UserSession {
        id_token: id_token.unwrap().to_string(),
    };

    auth.cache
        .set(
            format!("claim:{session_key}").as_str(),
            serde_json::to_string(&user_session).unwrap().as_str(),
        )
        .await
        .map_err(|_| OidcError::OAuthError)?;

    Ok(Redirect::to("/"))
}
