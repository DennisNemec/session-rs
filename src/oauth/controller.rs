use std::fmt::Debug;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    app::AppState,
    cache::TCache,
    claims::TClaimStore,
    session::{TSession, TSessionFactory, TSessionHandler, SESSION_KEY},
};

pub async fn handle_request<
    SessionHandler: TSessionHandler,
    ClaimHandler: TClaimStore,
    Cache: TCache,
    Factory: TSessionFactory<Session>,
    Session: TSession + Debug + Serialize + DeserializeOwned + Send + Sync,
>(
    jar: CookieJar,
    State(AppState {
        cache,
        factory,
        session,
        claim,
    }): State<AppState<Cache, SessionHandler, Factory, ClaimHandler>>,
    request: Request,
) -> Response {
    let path = Some(request.uri().to_string());

    if let Some(v) = path {
        if v == "/login".to_string() {
            return handle_login_request(
                jar,
                State(AppState {
                    cache,
                    factory,
                    session,
                    claim,
                }),
            )
            .await;
        }

        if v == "/auth/callback".to_string() {
            return handle_oauth_callback(
                jar,
                State(AppState {
                    cache,
                    factory,
                    session,
                    claim,
                }),
            )
            .await;
        }
    }

    let session_id_option = jar.get(SESSION_KEY).map(|c| c.value().to_owned());
    if session_id_option.is_none() {
        return Redirect::to("/login").into_response();
    }

    let session_id = session_id_option.unwrap();
    let cache_result = cache
        .get::<Session>(&format!("session:{session_id}").to_string())
        .await;
    if cache_result.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    if cache_result.unwrap().is_some() {
        return StatusCode::OK.into_response();
    }

    let session_result = session.get(&session_id).await;
    if session_result.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let session = session_result.unwrap();
    if session.is_none() {
        return Redirect::to("/login").into_response();
    }

    let insert_cache_res = cache.set(&session_id, session.clone().unwrap()).await;
    if insert_cache_res.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let session_unwrapped = session.unwrap();
    let user_id = session_unwrapped.user_id();

    let claim_cache_result = cache
        .get::<String>(&format!("claim:{user_id}").to_string())
        .await;

    if claim_cache_result.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let claim_get_result = claim.get_claim(&user_id).await;
    if claim_get_result.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let claim_unwrapped = claim_get_result.unwrap();
    if claim_unwrapped.is_none() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let claim_cache_res = cache
        .set(
            &format!("claim:{user_id}").to_string(),
            claim_unwrapped.clone().unwrap(),
        )
        .await;

    if claim_cache_res.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }

    println!(
        "AUTHENTICATION SUCCESSFUL: CLAIM for {user_id}: {:?}",
        claim_unwrapped.unwrap()
    );

    StatusCode::OK.into_response()
}

pub async fn handle_login_request<
    SessionHandler: TSessionHandler,
    ClaimHandler: TClaimStore,
    Cache: TCache,
    Factory: TSessionFactory<Session>,
    Session: TSession + Serialize + DeserializeOwned + Send + Sync,
>(
    _jar: CookieJar,
    State(AppState {
        cache: _,
        factory: _,
        session: _,
        claim: _,
    }): State<AppState<Cache, SessionHandler, Factory, ClaimHandler>>,
) -> Response {
    println!("LOGIN");

    StatusCode::OK.into_response()
}

pub async fn handle_oauth_callback<
    SessionHandler: TSessionHandler,
    ClaimHandler: TClaimStore,
    Cache: TCache,
    Factory: TSessionFactory<Session>,
    Session: TSession + Serialize + DeserializeOwned + Send + Sync,
>(
    jar: CookieJar,
    State(AppState {
        cache: _,
        factory: _,
        session: _,
        claim: _,
    }): State<AppState<Cache, SessionHandler, Factory, ClaimHandler>>,
) -> Response {
    let session_id = jar.get(SESSION_KEY).map(|c| c.value().to_owned());

    if session_id.is_none() {
        let _ = jar.add(Cookie::new("URI", "HAHA"));
        let _ = Redirect::to("/login");
    }

    StatusCode::OK.into_response()
}
