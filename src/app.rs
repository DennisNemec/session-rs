use std::{fs::File, io::Read};

use axum::{
    body::Body,
    error_handling::HandleErrorLayer,
    extract::Request,
    response::{IntoResponse, Response},
    routing::get,
    BoxError, Router,
};
use reqwest::StatusCode;
use tower::ServiceBuilder;

use crate::{
    builder::ApiGatewayConfiguration,
    cache::RedisCache,
    oidc::{service::AuthLayer, OidcError, OidcState},
    reverse_proxy::{service::ReverseProxyLayer, PathDefinition},
    session::{CachedSessionStore, SessionStore},
};

pub struct App {
    path_definitions: Vec<PathDefinition>,
    oidc_state: Option<OidcState>,
    cache: Option<RedisCache>,
    store: Option<CachedSessionStore<RedisCache, SessionStore>>,
    address: String,
    port: u16
}

async fn forward_request(request: Request) -> impl IntoResponse {
    let headers = request.headers().clone();
    let client = reqwest::Client::new();
    let req = client
        .request(
            request.method().clone(),
            format!(
                "{}{:?}",
                headers.get("host").unwrap().to_str().unwrap(),
                request.uri()
            ),
        )
        .headers(headers)
        .build()
        .unwrap();

    let result = client.execute(req).await;
    if let Ok(res) = result {
        let mut response_builder = Response::builder().status(res.status());
        *response_builder.headers_mut().unwrap() = res.headers().clone();
        response_builder
            .body(Body::from_stream(res.bytes_stream()))
            .unwrap()
    } else {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl App {
    pub fn path(mut self, path: PathDefinition) -> Self {
        self.path_definitions.push(path);

        self
    }

    pub async fn new_from_cfg_file(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config_file = File::open(config_path)?;
        let mut config_content = String::new();

        config_file.read_to_string(&mut config_content)?;

        let config = serde_yml::from_str::<ApiGatewayConfiguration>(&config_content)?;

        let is_any_path_protected = config.paths.iter().any(|path| path.protected.is_some());
        if is_any_path_protected && config.oidc.is_none() {
            return Err(
                "OIDC configuration not found! OIDC configuration is required for protected paths."
                    .into(),
            );
        }

        if config.oidc.is_some() && config.cache.is_none() {
            return Err(
                "Protection for paths requires a cache. Currently a RedisCache is supported."
                    .into(),
            );
        }

        if config.oidc.is_some() && config.store.is_none() {
            return Err(
                "Protection for paths requires a session store that implements TSessionStore."
                    .into(),
            );
        }

        let cache = if let Some(cache) = &config.cache {
            let cache = RedisCache::try_new(&cache.url);

            if let Err(e) = cache {
                return Err(format!("Failed to initialize cache! Error: {:?}", e).into());
            }

            Some(cache.unwrap())
        } else {
            None
        };

        let store = if config.oidc.is_some() && config.cache.is_some() && config.store.is_some() {
            Some(CachedSessionStore::new(
                cache.clone().unwrap(),
                config.store.unwrap(),
            ))
        } else {
            None
        };

        Ok(Self {
            address: config.address,
            port: config.port,
            cache,
            store,
            path_definitions: config.paths,
            oidc_state: if let Some(oidc) = config.oidc {
                Some(
                    OidcState::new(
                        &oidc.issuer_url,
                        &oidc.client_id,
                        &oidc.client_secret,
                        &oidc.redirect_uri,
                        &oidc.callback_path,
                        &oidc.login_path,
                        &oidc.logout_path,
                    )
                    .await?,
                )
            } else {
                None
            },
        })
    }

    pub async fn run(self) {
        let address = self.address;
        let port = self.port;

        let listener: tokio::net::TcpListener =
            tokio::net::TcpListener::bind(format!("{address}:{port}"))
                .await
                .expect("Not able to bind listener");

        let mut router = Router::new()
            .route("/*0", get(forward_request))
            .route("/", get(forward_request))
            .layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(handle_oidc_error))
                    .layer(ReverseProxyLayer::new(self.path_definitions)),
            );

        if let Some(state) = self.oidc_state {
            router = router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(handle_oidc_error))
                    .layer(AuthLayer::new(
                        state,
                        self.store.unwrap(),
                        self.cache.unwrap(),
                    )),
            );
        }

        axum::serve(listener, router).await.unwrap();
    }
}

async fn handle_oidc_error(err: BoxError) -> impl IntoResponse {
    if err.is::<OidcError>() {
        err.downcast::<OidcError>().unwrap().into_response()
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {err}"),
        )
            .into_response()
    }
}
