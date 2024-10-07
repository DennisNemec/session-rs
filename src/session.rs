use bson::Uuid;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::HashMap, sync::{Arc, RwLock}
};

use crate::app::AppError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user_id: Uuid,
    pub payload: String,
}

impl Session {
    pub fn new(user_id: Uuid, payload: String) -> Self {
        Self {
            session_id: Uuid::new().to_string(),
            user_id,
            payload,
        }
    }
}

#[derive(Clone)]
pub struct SessionFactory;

impl SessionFactory {
    pub fn new() -> Self {
        Self {}
    }
}

impl TSessionFactory<Session> for SessionFactory {
    fn make<P: DeserializeOwned + Serialize + Sync + Send>(&self, _payload: P) -> Session {
        Session::new(Uuid::new(), "payload".to_string())
    }
}

impl TSession for Session {
    fn session_id(&self) -> String {
        self.session_id.clone()
    }
}

pub trait TSessionFactory<Session> {
    fn make<P: DeserializeOwned + Serialize + Sync + Send>(&self, payload: P) -> Session;
}

pub trait TSession {
    fn session_id(&self) -> String;
}

#[async_trait::async_trait]
pub trait TSessionHandler {
    type Session: TSession + Serialize + DeserializeOwned + Send + Sync + 'static;
    type Error;

    async fn get(&self, id: &String) -> Result<Option<Self::Session>, Self::Error>;
    async fn insert(
        &mut self,
        id: String,
        session: Self::Session,
    ) -> Result<Self::Session, Self::Error>;
    async fn delete(&mut self, id: &String) -> Result<(), Self::Error>;
}

#[derive(Clone)]
pub struct SessionService {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl SessionService {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn session_get(&self, key: &String) -> Option<Session> {
        let list = self.sessions.clone();
        let value = list.read().unwrap().get::<String>(key).cloned();

        value
    }

    pub fn session_add(&mut self, key: String, session: Session) {
        let list = self.sessions.clone();
        list.write().unwrap().insert(key, session);
    }

    pub fn session_delete(&mut self, key: &String) {
        let list = self.sessions.clone();
        list.write().unwrap().remove(key);
    }
}

#[async_trait::async_trait]
impl TSessionHandler for SessionService {
    type Session = Session;

    type Error = AppError;

    async fn get(&self, session_id: &String) -> Result<Option<Self::Session>, Self::Error> {
        Ok(self.session_get(session_id))
    }

    async fn insert(
        &mut self,
        id: String,
        session: Self::Session,
    ) -> Result<Self::Session, Self::Error> {
        self.session_add(id, session.clone());

        Ok(session)
    }

    async fn delete(&mut self, id: &String) -> Result<(), Self::Error> {
        self.session_delete(id);

        Ok(())
    }
}
