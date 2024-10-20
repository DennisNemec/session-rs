use axum::{body::Body, extract::Request, response::Response, BoxError};
use futures_util::future::BoxFuture;
use tower::{Layer, Service};

use crate::{cache::TCache, oidc::OidcError};

#[derive(Clone)]
pub struct SessionLayer<C: TCache> {
    cache: C,
}

impl<C: TCache> SessionLayer<C> {
    pub fn new(cache: C) -> Self {
        Self { cache }
    }
}

impl<S, C: TCache> Layer<S> for SessionLayer<C> {
    type Service = SessionService<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        SessionService::new(inner, self.cache.clone())
    }
}

#[derive(Clone)]
pub struct SessionService<S, C: TCache> {
    inner: S,
    cache: C,
}

impl<S, C: TCache> SessionService<S, C> {
    pub fn new(inner: S, cache: C) -> Self {
        Self { inner, cache }
    }
}

impl<S, C: TCache> Service<Request<Body>> for SessionService<S, C>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Error: Send + Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let future: <S as Service<axum::http::Request<Body>>>::Future = self.inner.call(req);
        Box::pin(async move { Err(OidcError::OAuthError.into()) })
    }
}
