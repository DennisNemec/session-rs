use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cache::{CacheError, TCache};

use super::AuthError;

#[async_trait]
pub trait TClaimStore: Clone {
    async fn get_claim(&self, user_id: &str) -> Result<Option<Claim>, AuthError>;
    async fn get_claim_by_mail(&self, mail: &str) -> Result<Option<Claim>, AuthError>;
}

#[derive(Clone, Debug)]
pub struct InMemoryClaimService {
    claims: Arc<RwLock<HashMap<String, Claim>>>,
}

impl Default for InMemoryClaimService {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryClaimService {
    pub fn new() -> Self {
        Self {
            claims: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_claim(&mut self, user_id: &str, payload: &str) {
        let store_cloned = self.claims.clone();
        store_cloned.write().unwrap().insert(
            user_id.to_string().clone(),
            Claim {
                user_id: user_id.to_string().clone(),
                payload: serde_json::from_str(payload).unwrap(),
            },
        );
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claim {
    pub user_id: String,
    pub payload: Value,
}

#[async_trait]
impl TClaimStore for InMemoryClaimService {
    async fn get_claim(&self, user_id: &str) -> Result<Option<Claim>, AuthError> {
        let claims_cloned = self.claims.clone();
        let claim = claims_cloned.read().unwrap().get(user_id).cloned();

        if claim.is_none() {
            Ok(None)
        } else {
            Ok(Some(claim.unwrap()))
        }
    }

    async fn get_claim_by_mail(&self, user_id: &str) -> Result<Option<Claim>, AuthError> {
        let claims_cloned = self.claims.clone();
        let claim = claims_cloned.read().unwrap().get(user_id).cloned();

        if claim.is_none() {
            Ok(None)
        } else {
            Ok(Some(claim.unwrap()))
        }
    }
}

#[derive(Clone)]
pub struct ClaimCache<Cache: TCache + Clone + Sync + Send> {
    pub cache: Cache,
}

impl<Cache: TCache + Clone + Sync + Send> ClaimCache<Cache> {
    fn get_key(&self, user_id: &str) -> String {
        format!("claim:{user_id}")
    }

    pub async fn get_claim(&self, user_id: &str) -> Result<Option<Claim>, CacheError> {
        let entry = self.cache.get(self.get_key(user_id).as_str()).await?;

        if entry.is_none() {
            return Ok(None);
        }

        Ok(Some(
            serde_json::from_str::<Claim>(entry.unwrap().as_str())
                .map_err(CacheError::FormatError)?,
        ))
    }

    pub async fn add_claim(&self, user_id: &str, claim_payload: &str) -> Result<(), CacheError> {
        self.cache
            .set(self.get_key(user_id).as_str(), claim_payload)
            .await
    }
}
