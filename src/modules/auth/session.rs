/*use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, RwLock},
};

use crate::cache::{CacheError, TCache};

pub const SESSION_KEY: &str = "id";

#[async_trait::async_trait]
pub trait TSessionHandler: Clone {
    async fn get(&self, id: &str) -> Result<Option<String>, AuthError>;
    async fn insert(&mut self, session_id: &str, user_id: &str) -> Result<String, AuthError>;
    async fn delete(&mut self, id: &str) -> Result<(), AuthError>;
}

#[derive(Clone, Debug)]
pub struct InMemorySessionService {
    sessions: Arc<RwLock<HashMap<String, String>>>,
}

impl Default for InMemorySessionService {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemorySessionService {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn session_get(&self, session_id: &str) -> Option<String> {
        let list = self.sessions.clone();
        let value = list
            .read()
            .unwrap()
            .get::<String>(&session_id.to_string())
            .cloned();

        value
    }

    pub fn session_add(&mut self, session_id: &str, user_id: &str) {
        let list = self.sessions.clone();
        list.write()
            .unwrap()
            .insert(session_id.to_string(), user_id.to_string());
    }

    pub fn session_delete(&mut self, key: &str) {
        let list = self.sessions.clone();
        list.write().unwrap().remove(key);
    }
}

#[async_trait::async_trait]
impl TSessionHandler for InMemorySessionService {
    async fn get(&self, session_id: &str) -> Result<Option<String>, AuthError> {
        Ok(self.session_get(session_id))
    }

    async fn insert(&mut self, session_id: &str, user_id: &str) -> Result<String, AuthError> {
        self.session_add(session_id, user_id);

        Ok(session_id.to_string())
    }

    async fn delete(&mut self, id: &str) -> Result<(), AuthError> {
        self.session_delete(id);

        Ok(())
    }
}

#[derive(Clone)]
pub struct SessionCache<Cache: TCache + Clone + Sync + Send> {
    pub cache: Cache,
}

impl<Cache: TCache + Clone + Sync + Send> SessionCache<Cache> {
    fn get_key(&self, session_id: &str) -> String {
        format!("session:{session_id}")
    }

    pub async fn get_session(&self, session_id: &str) -> Result<Option<String>, CacheError> {
        let entry = self.cache.get(self.get_key(session_id).as_str()).await?;

        if entry.is_none() {
            return Ok(None);
        }

        Ok(Some(entry.unwrap()))
    }

    pub async fn add_session(&self, session_id: &str, user_id: &str) -> Result<(), CacheError> {
        self.cache
            .set(self.get_key(session_id).as_str(), user_id)
            .await
    }
}*/
