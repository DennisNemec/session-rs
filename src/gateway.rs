use axum::extract::State;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    app::AppState,
    cache::TCache,
    session::{TSession, TSessionFactory, TSessionHandler},
};

pub async fn handler<
    SessionHandler: TSessionHandler,
    Cache: TCache,
    Factory: TSessionFactory<Session>,
    Session: TSession + Serialize + DeserializeOwned + Send + Sync,
>(
    State(AppState {
        cache,
        factory: _,
        session: _,
    }): State<AppState<Cache, SessionHandler, Factory>>,
) {
    let result = cache.get(&"test".to_string()).await;

    if result.is_err() {
        
    }
}
