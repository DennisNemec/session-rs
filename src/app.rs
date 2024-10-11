use axum::{
    body::Body,
    extract::{Request, State},
    http::HeaderValue,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use reqwest::StatusCode;

use crate::{
    cache::TCache, modules::oidc::{oidc_auth, OidcConfiguration},

};

#[derive(Clone)]
pub struct GatewayConfiguration {
    pub forward_address: String,
}

pub struct App;

async fn forward_request(
    State(GatewayConfiguration { forward_address }): State<GatewayConfiguration>,
    request: Request,
) -> Response {
    let mut headers = request.headers().clone();
    *headers.get_mut("host").unwrap() = HeaderValue::from_str(&forward_address).unwrap();

    let client = reqwest::Client::new();
    let req = client
        .request(
            request.method().clone(),
            format!(
                "http://{}{:?}",
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
    pub async fn run<Cache: TCache + Clone + Sync + Send + 'static>(
        address: &str,
        port: u16,
        auth_state: OidcConfiguration<Cache>,
        forward_address: &str,
    ) {
        let listener: tokio::net::TcpListener =
            tokio::net::TcpListener::bind(format!("{address}:{port}"))
                .await
                .expect("Not able to bind listener");

        let router = Router::new()
            .route("/*0", get(forward_request))
            .route("/", get(forward_request))
            .with_state(GatewayConfiguration {
                forward_address: forward_address.to_string(),
            })
            .layer(from_fn_with_state(auth_state.clone(), oidc_auth))
            .with_state(auth_state);

        axum::serve(listener, router).await.unwrap();
    }
}
