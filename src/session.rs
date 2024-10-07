use bson::Uuid;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, RwLock},
};

use crate::app::AppError;

pub const SESSION_KEY: &str = "id";

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

    fn user_id(&self) -> String {
        self.user_id.to_string().clone()
    }
}
pub trait TSessionFactory<Session>: Clone {
    fn make<P: DeserializeOwned + Serialize + Sync + Send>(&self, payload: P) -> Session;
}

pub trait TSession {
    fn session_id(&self) -> String;
    fn user_id(&self) -> String;
}

#[async_trait::async_trait]
pub trait TSessionHandler: Clone {
    type Session: TSession + Serialize + DeserializeOwned + Send + Sync + 'static + Clone;
    type Error: Debug + Sync + Send;

    async fn get(&self, id: &String) -> Result<Option<Self::Session>, Self::Error>;
    async fn insert(
        &mut self,
        id: String,
        session: Self::Session,
    ) -> Result<Self::Session, Self::Error>;
    async fn delete(&mut self, id: &String) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug)]
pub struct InMemorySessionService {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl InMemorySessionService {
    pub fn new() -> Self {
        // TODO: remove
        let mut tmp = HashMap::new();
        tmp.insert(
            "test".to_string(),
            Session {
                session_id: Uuid::new().to_string(),
                user_id: Uuid::parse_str("d504295f-b9d9-4742-bd19-842ae87906ce").unwrap(),
                payload: "".to_string(),
            },
        );

        Self {
            sessions: Arc::new(RwLock::new(tmp)),
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
impl TSessionHandler for InMemorySessionService {
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
