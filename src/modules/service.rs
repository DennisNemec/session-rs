use std::{future::Future, pin::Pin};

use axum::{
    body::Body,
    extract::Query,
    http::{HeaderValue, Request, Response},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::CookieJar;
use reqwest::Method;
use tower::{Layer, Service};

use crate::{
    cache::TCache,
    modules::oidc::{
        handle_login_request, handle_oauth_callback, OAuthCallbackQuery, OidcError, UserSession,
        SESSION_KEY,
    },
};

use super::oidc::OidcConfiguration;

#[derive(Clone)]
pub struct AuthLayer<C: TCache> {
    config: OidcConfiguration<C>,
}

impl<C: TCache> AuthLayer<C> {
    pub fn new(config: OidcConfiguration<C>) -> Self {
        Self { config }
    }
}

impl<S, C: TCache> Layer<S> for AuthLayer<C> {
    type Service = OpenIdConnectService<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        OpenIdConnectService::new(inner, self.config.clone())
    }
}

#[derive(Clone)]
pub struct OpenIdConnectService<S, C: TCache> {
    inner: S,
    oidc_config: OidcConfiguration<C>,
}

impl<S, C: TCache> OpenIdConnectService<S, C> {
    pub fn new(inner: S, oidc_config: OidcConfiguration<C>) -> Self {
        Self { inner, oidc_config }
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

impl<S, C> Service<Request<Body>> for OpenIdConnectService<S, C>
where
    S::Future: Send,
    C: TCache + 'static,
    S::Error: Into<BoxError>,
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let auth = self.oidc_config.clone();

        Box::pin(async move {
            fn add_session_header(request: &mut Request<Body>, session: String) {
                let mutable_header = request.headers_mut();

                mutable_header.insert(
                    "Authorization",
                    HeaderValue::from_str(format!("Bearer {}", session).as_str()).unwrap(),
                );
            }

            let jar = CookieJar::from_headers(request.headers());
            let session_key = jar.get(SESSION_KEY).map(|c| c.value());

            if let Some(s) = session_key {
                let result = auth
                    .cache
                    .get(format!("claim:{s}").as_str())
                    .await
                    .map_err(|_| Box::new(OidcError::OAuthError))?;

                if let Some(serialized_session) = result {
                    let session = serde_json::from_str::<UserSession>(&serialized_session)
                        .map_err(|_| OidcError::OAuthError)?;
                    add_session_header(&mut request, session.id_token);
                    return inner.call(request).await.map_err(Into::into);
                }
            }

            let path = Some(request.uri().path().to_string());
            let method = request.method();
            if let Some(v) = path {
                if v == auth.login_url {
                    // Perform OIDC authentication
                    if method == Method::POST {
                        return Ok(handle_login_request(&auth, &jar)
                            .await
                            .map_err(|_| OidcError::OAuthError)?
                            .into_response());
                    }

                    // Forward to downstream login page
                    if method == Method::GET {
                        return inner.call(request).await.map_err(Into::into);
                    }
                } else if v == auth.callback_url {
                    let Query(OAuthCallbackQuery { code, state, error }) =
                        if let Ok(query) = Query::try_from_uri(request.uri()) {
                            query
                        } else {
                            return Err(OidcError::OAuthError.into());
                        };

                    if let Some(code) = code {
                        return Ok(handle_oauth_callback(&jar, code, state, &auth)
                            .await
                            .map_err(|_| OidcError::OAuthError)?
                            .into_response());
                    } else if let Some(error) = error {
                        return Ok(Redirect::to(
                            format!("{}?error={}", &auth.login_url, error).as_str(),
                        )
                        .into_response());
                    } else {
                        // The OIDC provider did not provide error information
                        return Err(OidcError::OAuthError.into());
                    }
                } else {
                    return Ok(Redirect::to(&auth.login_url).into_response());
                }
            }

            inner.call(request).await.map_err(Into::into)
        })
    }
}
