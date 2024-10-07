use std::fmt::Display;

use axum::{routing::get, Router};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    cache::TCache,
    gateway::handler,
    session::{TSession, TSessionFactory, TSessionHandler},
};

#[derive(Clone)]
pub struct AppState<Cache, SessionHandler, SessionFactory> {
    pub cache: Cache,
    pub session: SessionHandler,
    pub factory: SessionFactory,
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
    >(
        address: &str,
        port: u16,
        cache: Cache,
        session: SessionHandler,
        factory: SessionFactory,
    ) -> Result<(), AppError> {
        let listener = tokio::net::TcpListener::bind(format!("{address}:{port}"))
            .await
            .map_err(AppError::Tokio)?;
        let state = AppState {
            cache,
            session,
            factory,
        };

        let router = Router::new()
            .route(
                "/",
                get(handler::<SessionHandler, Cache, SessionFactory, Session>),
            )
            .with_state(state);

        axum::serve(listener, router).await.unwrap();

        Ok(())
    }
}
