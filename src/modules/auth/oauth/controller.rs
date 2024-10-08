use axum::{
    extract::{Query, Request, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use bson::Uuid;
use oauth2::{reqwest::async_http_client, AuthorizationCode, TokenResponse};

use crate::{
    cache::TCache,
    modules::auth::{
        claims::TClaimStore,
        session::{TSessionHandler, SESSION_KEY},
        AuthError, TPerson, CSRF_OLD_KEY,
    },
};

use super::{OAuthCallbackQuery, OAuthState, TOAuthGetPersonInfo};

pub async fn handle_request<
    Person: TOAuthGetPersonInfo,
    SessionHandler: TSessionHandler,
    ClaimHandler: TClaimStore,
    Cache: TCache + Send + Sync,
>(
    jar: CookieJar,
    State(OAuthState {
        session_cache,
        claim_cache,
        session,
        claim,
        auth,
    }): State<OAuthState<Cache, SessionHandler, ClaimHandler, Person>>,
    request: Request,
) -> Result<Response, AuthError> {
    let path = Some(request.uri().path().to_string());

    if let Some(v) = path {
        if v == *"/login" {
            return Ok(handle_login_request(
                jar,
                State(OAuthState {
                    session_cache,
                    claim_cache,
                    session,
                    claim,
                    auth,
                }),
            )
            .await?
            .into_response());
        }

        if v == *"/auth/callback" {
            let query = Query::try_from_uri(request.uri());

            if query.is_err() {
                return Err(AuthError::OAuthError);
            }

            return Ok(handle_oauth_callback(
                jar,
                query.unwrap(),
                State(OAuthState {
                    session_cache: session_cache.clone(),
                    claim_cache: claim_cache.clone(),
                    session: session.clone(),
                    claim: claim.clone(),
                    auth: auth.clone(),
                }),
            )
            .await?
            .into_response());
        }
    }

    let session_id_option = jar.get(SESSION_KEY).map(|c| c.value().to_owned());
    if session_id_option.is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let session_id = session_id_option.unwrap();
    let session_cache_entry = session_cache
        .get_session(&session_id)
        .await
        .map_err(AuthError::CacheError)?;
    if session_cache_entry.is_some() {
        return Ok(StatusCode::OK.into_response());
    }

    // No session available in Cache. Therefore, ask the session management unit
    // if the session is valid.
    let session_cache_entry = session.get(&session_id).await?;

    if session_cache_entry.is_none() {
        // Session is invalid. Redirect to login page.
        return Ok(Redirect::to("/login").into_response());
    }

    let session_user_id = session_cache_entry.unwrap();

    // Session is valid, but not in cache yet. Add it to cache.
    session_cache
        .add_session(&session_id, &session_user_id)
        .await
        .map_err(AuthError::CacheError)?;

    // Step 2: Get claim
    let claim_cache_entry = claim_cache
        .get_claim(&session_user_id)
        .await
        .map_err(AuthError::CacheError)?;

    // VALID CLAIM AVAILABLE
    if let Some(claim_payload) = claim_cache_entry {
        return Ok(Json(claim_payload).into_response());
    }

    // Claim is not in cache. Therefore, ask the claim manager for a valid claim.
    let claim = claim.get_claim(&session_user_id).await?;

    // No valid claim available. The user is not registered yet and therefore unauthorized to access the page.
    if claim.is_none() {
        return Err(AuthError::Unauthorized);
    }

    // Claim is available. Store it in cache.
    claim_cache
        .add_claim(&session_user_id, &claim.unwrap().payload.to_string())
        .await
        .map_err(AuthError::CacheError)?;

    // TEST: Print YEAH
    Ok("YEAH YOU ARE VALID".into_response())
}

pub async fn handle_login_request<
    PersonEndpoint: TOAuthGetPersonInfo,
    SessionHandler: TSessionHandler,
    ClaimHandler: TClaimStore,
    Cache: TCache + Send + Sync,
>(
    jar: CookieJar,
    State(OAuthState {
        session_cache: _,
        claim_cache: _,
        session: _,
        claim: _,
        auth,
    }): State<OAuthState<Cache, SessionHandler, ClaimHandler, PersonEndpoint>>,
) -> Result<impl IntoResponse, AuthError> {
    let (auth_url, old_token) = auth.authorize_url();

    Ok((
        jar.add(Cookie::new(CSRF_OLD_KEY, old_token.secret().to_string())),
        Redirect::to(auth_url.as_str()),
    ))
}

pub async fn handle_oauth_callback<
    PersonEndpoint: TOAuthGetPersonInfo,
    SessionHandler: TSessionHandler,
    ClaimHandler: TClaimStore,
    Cache: TCache + Send + Sync,
>(
    jar: CookieJar,
    Query(OAuthCallbackQuery {
        code,
        state: csrf_token,
    }): Query<OAuthCallbackQuery>,

    State(OAuthState {
        session_cache,
        claim_cache: _,
        session: _,
        claim,
        auth,
    }): State<OAuthState<Cache, SessionHandler, ClaimHandler, PersonEndpoint>>,
) -> Result<impl IntoResponse, AuthError> {
    let Some(cookie) = jar.get(CSRF_OLD_KEY) else {
        return Err(AuthError::InvalidCookie);
    };

    if cookie.value() != *csrf_token.secret() {
        return Err(AuthError::InvalidCsrfToken);
    }

    let token_result = auth
        .client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await;

    if token_result.is_err() {
        return Err(AuthError::OAuthError);
    }

    let token = token_result.unwrap().access_token().secret().to_owned();
    let user_result = auth.person.get_information(token).await;

    if user_result.is_err() {
        return Err(AuthError::OAuthError);
    }

    let mail = user_result.unwrap().get_mail();
    let claim_option = claim.get_claim_by_mail(&mail).await?;

    if claim_option.is_none() {
        return Err(AuthError::Unauthorized);
    }

    let claim = claim_option.unwrap();
    let session_id = Uuid::new().to_string();
    session_cache
        .add_session(&session_id, claim.user_id.as_str())
        .await
        .map_err(AuthError::CacheError)?;

    let mut cookie = Cookie::new(SESSION_KEY, session_id);
    cookie.set_path("/");

    Ok((jar.add(cookie), Redirect::to("/")))
}
