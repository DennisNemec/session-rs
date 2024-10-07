use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

use crate::app::AppError;

#[async_trait]
pub trait TClaimStore {
    type Error: Debug + Sync + Send;
    type Claim: Debug + Clone + Serialize + DeserializeOwned + Send + Sync;

    async fn get_claim(
        &self,
        user_id: &String,
    ) -> Result<Option<Self::Claim>, Self::Error>;
}

#[derive(Clone, Debug)]
pub struct InMemoryClaimService {
    claims: Arc<RwLock<HashMap<String, String>>>,
}

impl InMemoryClaimService {
    pub fn new() -> Self {
        let test = String::from("d504295f-b9d9-4742-bd19-842ae87906ce");

        let mut hashmap: HashMap<String, String> = HashMap::new();
        hashmap.insert(test, String::from("{\"data\": \"doener\"}"));

        Self {
            claims: Arc::new(RwLock::new(hashmap)),
        }
    }
}

#[async_trait]
impl TClaimStore for InMemoryClaimService {
    type Error = AppError;
    type Claim = String;

    async fn get_claim(&self, user_id: &String) -> Result<Option<Self::Claim>, Self::Error> {
        let claims_cloned = self.claims.clone();
        let claim = claims_cloned.read().unwrap().get(user_id).cloned();

        Ok(claim)
    }
}
