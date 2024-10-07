use std::fmt::Display;

use axum::Router;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    cache::TCache, claims::TClaimStore, session::{TSession, TSessionFactory, TSessionHandler}
};

#[derive(Clone)]
pub struct AppState<Cache, SessionHandler, SessionFactory, ClaimHandler> {
    pub cache: Cache,
    pub session: SessionHandler,
    pub factory: SessionFactory,
    pub claim: ClaimHandler
}

pub struct App;

#[derive(Debug)]
pub enum AppError {
    Tokio(std::io::Error),
    Redis(redis::RedisError),
    Json(serde_json::Error),
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TEST")
    }
}

impl App {
    pub async fn run<
        Session: TSession + Serialize + DeserializeOwned + Send + Sync + 'static,
        Cache: TCache + 'static + Clone + Send + Sync,
        SessionHandler: TSessionHandler + 'static + Clone + Send + Sync,
        SessionFactory: TSessionFactory<Session> + 'static + Clone + Send + Sync,
        ClaimHandler: TClaimStore + 'static + Clone + Send + Sync,
    >(
        address: &str,
        port: u16,
        cache: Cache,
        session: SessionHandler,
        factory: SessionFactory,
        claim: ClaimHandler,
        routes: Router<AppState<Cache, SessionHandler, SessionFactory, ClaimHandler>>
    ) -> Result<(), AppError> {
        let listener = tokio::net::TcpListener::bind(format!("{address}:{port}"))
            .await
            .map_err(AppError::Tokio)?;
        let state = AppState {
            cache,
            session,
            factory,
            claim
        };

        let router = Router::new()
            .merge(routes)
            .with_state(state);

        axum::serve(listener, router).await.unwrap();

        Ok(())
    }
}
