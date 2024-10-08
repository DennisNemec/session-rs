pub mod controller;
pub mod google;
pub mod routes;

use std::fmt::Debug;

use axum::async_trait;
use oauth2::{
    basic::BasicClient, url::Url, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenUrl,
};
use serde::{Deserialize, Serialize};

use crate::cache::TCache;

use super::{claims::ClaimCache, session::SessionCache, TPerson};

#[derive(Clone)]
pub struct OAuthState<
    Cache: TCache + Clone + Sync + Send,
    SessionHandler,
    ClaimHandler,
    PersonEndpoint: TOAuthGetPersonInfo,
> {
    pub session_cache: SessionCache<Cache>,
    pub claim_cache: ClaimCache<Cache>,
    pub session: SessionHandler,
    pub claim: ClaimHandler,
    pub auth: OAuth<PersonEndpoint>,
}

impl<
        Cache: TCache + Clone + Sync + Send,
        SessionHandler,
        ClaimHandler,
        Person: TOAuthGetPersonInfo,
    > OAuthState<Cache, SessionHandler, ClaimHandler, Person>
{
    pub fn new(cache: Cache, session: SessionHandler, claim: ClaimHandler, auth: OAuth<Person>) -> Self {
        Self {
            session_cache: SessionCache { cache: cache.clone()},
            claim_cache: ClaimCache {cache: cache.clone()},
            session,
            claim,
            auth,
        }
    }
}

#[derive(Clone)]
pub struct OAuth<PersonEndpoint: TOAuthGetPersonInfo> {
    scopes: Vec<String>,
    client: BasicClient,
    person: PersonEndpoint,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthCredentials {
    pub code: String,
    pub token_old: CsrfToken,
    pub token_new: CsrfToken,
}

#[async_trait]
pub trait TOAuthGetPersonInfo: Clone {
    type Error: Debug + Send + Sync + 'static;
    type Person: TPerson;

    async fn get_information(&self, access_token: String) -> Result<Self::Person, Self::Error>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthCallbackQuery {
    code: String,
    state: CsrfToken,
}

impl<Person: TOAuthGetPersonInfo> OAuth<Person> {
    pub fn new(
        client_id: String,
        client_secret: String,
        auth_url: String,
        token_url: String,
        redirect_url: String,
        scopes: Vec<String>,
        person_endpoint: Person,
    ) -> Self {
        let mut client = BasicClient::new(
            ClientId::new(client_id.clone()),
            Some(ClientSecret::new(client_secret.clone())),
            AuthUrl::new(auth_url).unwrap(),
            Some(TokenUrl::new(token_url).unwrap()),
        );

        client = client.set_redirect_uri(RedirectUrl::new(redirect_url.clone()).unwrap());

        Self {
            scopes,
            client,
            person: person_endpoint,
        }
    }

    pub fn authorize_url(&self) -> (Url, CsrfToken) {
        self.client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(self.scopes.clone().into_iter().map(Scope::new))
            .url()
    }
}
