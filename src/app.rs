use axum::Router;
use std::fmt::Display;

use crate::{
    cache::TCache,
    modules::auth::{
        claims::TClaimStore,
        oauth::{OAuthState, TOAuthGetPersonInfo},
        session::TSessionHandler,
        AuthError,
    },
};

pub struct App;

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TEST")
    }
}

impl App {
    pub async fn run<
        Person: TOAuthGetPersonInfo + 'static + Clone + Send + Sync,
        Cache: TCache + 'static + Clone + Send + Sync,
        SessionHandler: TSessionHandler + 'static + Clone + Send + Sync,
        ClaimHandler: TClaimStore + 'static + Clone + Send + Sync,
    >(
        address: &str,
        port: u16,
        (router, state): (
            Router<OAuthState<Cache, SessionHandler, ClaimHandler, Person>>,
            OAuthState<Cache, SessionHandler, ClaimHandler, Person>,
        ),
    ) -> Result<(), AuthError> {
        let listener = tokio::net::TcpListener::bind(format!("{address}:{port}"))
            .await
            .map_err(AuthError::Tokio)?;

        axum::serve(listener, Router::new().merge(router).with_state(state))
            .await
            .unwrap();

        Ok(())
    }
}
