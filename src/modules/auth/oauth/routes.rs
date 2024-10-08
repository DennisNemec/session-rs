use std::fmt::Debug;

use crate::{
    cache::TCache,
    modules::auth::{claims::TClaimStore, session::TSessionHandler},
};
use axum::{routing::get, Router};

use super::{controller::handle_request, OAuthState, TOAuthGetPersonInfo};

pub fn oauth_routes<
    Person: TOAuthGetPersonInfo + 'static + Clone + Send + Sync,
    Cache: TCache + 'static + Clone + Send + Sync,
    SessionHandler: TSessionHandler + 'static + Clone + Send + Sync,
    ClaimHandler: TClaimStore + 'static + Clone + Send + Sync + Debug,
>(
    state: OAuthState<Cache, SessionHandler, ClaimHandler, Person>,
) -> (
    Router<OAuthState<Cache, SessionHandler, ClaimHandler, Person>>,
    OAuthState<Cache, SessionHandler, ClaimHandler, Person>,
) {
    let merged_router = Router::new()
        .route("/*any", get(handle_request))
        .route("/", get(handle_request));

    (merged_router, state)
}
