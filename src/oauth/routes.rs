use std::fmt::Debug;

use axum::{routing::get, Router};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    app::AppState,
    cache::TCache,
    claims::TClaimStore,
    session::{TSession, TSessionFactory, TSessionHandler},
};

use super::controller::handle_request;

pub async fn oauth_routes<
    Session: TSession + Serialize + DeserializeOwned + Send + Sync + 'static + Debug,
    Cache: TCache + 'static + Clone + Send + Sync,
    SessionHandler: TSessionHandler + 'static + Clone + Send + Sync,
    SessionFactory: TSessionFactory<Session> + 'static + Clone + Send + Sync,
    ClaimHandler: TClaimStore + 'static + Clone + Send + Sync,
>() -> Router<AppState<Cache, SessionHandler, SessionFactory, ClaimHandler>> {
    Router::new()
        .route("/*any", get(handle_request))
        .route("/", get(handle_request))
}
