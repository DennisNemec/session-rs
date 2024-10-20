use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use bson::Uuid;
use openidconnect::reqwest::async_http_client;
use openidconnect::{AuthorizationCode, CsrfToken, OAuth2TokenResponse};

use crate::cache::TCache;
use crate::session::{Session, TSessionStore};

use super::{OidcState, OidcError, OidcSecurityInformation, SESSION_KEY};


pub async fn handle_login_request<Cache: TCache>(
    auth: &OidcState,
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
    auth: &OidcState,
    cache: &Cache,
    store: &S,
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

    store
        .set(&session)
        .await
        .map_err(|_| {
            OidcError::OAuthError
        })?;

    Ok(Redirect::to("/"))
}
