use serde::Deserialize;

use crate::{oidc::OidcConfiguration, reverse_proxy::PathDefinition, session::SessionStore};

#[derive(Deserialize, Debug, Clone)]
pub struct ApiGatewayConfiguration {
    pub paths: Vec<PathDefinition>,
    pub oidc: Option<OidcConfiguration>,
    pub cache: Option<CacheConfiguration>,
    pub store: Option<SessionStore>,
    pub address: String,
    pub port: u16
}

#[derive(Deserialize, Debug, Clone)]
pub struct CacheConfiguration {
    pub url: String
}
