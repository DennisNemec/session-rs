use axum::{
    body::Body,
    extract::{Query, Request},
    http::{HeaderValue, Uri},
    response::{IntoResponse, Response, Redirect},
};
use axum_extra::extract::CookieJar;
use futures_util::future::BoxFuture;
use openidconnect::{
    reqwest::async_http_client, AccessToken
};
use reqwest::Method;
use tower::{Layer, Service};

use crate::{
    cache::TCache,
    oidc::controller::{
        handle_login_request, handle_oauth_callback, OAuthCallbackQuery, OidcError,
        SESSION_KEY,
    },
    session::{Session, SessionError, TSessionStore},
};

use super::controller::OidcConfiguration;

#[derive(Clone)]
pub struct AuthLayer<T: TSessionStore + Clone, C: TCache> {
    config: OidcConfiguration,
    cache: C,
    store: T,
}

impl<T: TSessionStore + Clone, C: TCache> AuthLayer<T, C> {
    pub fn new(config: OidcConfiguration, store: T, cache: C) -> Self {
        Self {
            config,
            cache,
            store,
        }
    }
}

impl<S, T: TSessionStore + Clone, C: TCache> Layer<S> for AuthLayer<T, C> {
    type Service = OpenIdConnectService<S, T, C>;

    fn layer(&self, inner: S) -> Self::Service {
        OpenIdConnectService::new(
            inner,
            self.config.clone(),
            self.store.clone(),
            self.cache.clone(),
        )
    }
}


#[derive(Clone)]
pub struct OpenIdConnectService<S, T: TSessionStore + Clone, C: TCache> {
    inner: S,
    oidc_config: OidcConfiguration,
    store: T,
    cache: C,
}

impl<S, T: TSessionStore + Clone, C: TCache> OpenIdConnectService<S, T, C> {
    pub fn new(inner: S, oidc_config: OidcConfiguration, store: T, cache: C) -> Self {
        Self {
            inner,
            oidc_config,
            store,
            cache,
        }
    }

    async fn handle_logout<HC: TCache>(
        session: Session,
        auth: &OidcConfiguration,
        cache: HC,
    ) -> Result<(), SessionError> {
        let access_token = AccessToken::new(session.access_token);
        let revoke_request = auth
            .client
            .revoke_token(access_token.into())
            .map_err(|_| SessionError::SessionStoreError)?;

        revoke_request
            .request_async(async_http_client)
            .await
            .map_err(|_| SessionError::SessionStoreError)?;

        cache
            .delete(format!("session:{}", session.session_id).as_str())
            .await
            .map_err(|_| SessionError::SessionStoreError)?;

        Ok(())
    }

    async fn handle_oidc_callback<HC: TCache, SS: TSessionStore>(
        auth: &OidcConfiguration,
        cache: HC,
        jar: &CookieJar,
        uri: &Uri,
        store: &SS
    ) -> Result<Response<Body>, BoxError> {
        let Query(OAuthCallbackQuery { code, state, error }) =
            if let Ok(query) = Query::try_from_uri(uri) {
                query
            } else {
                return Err(OidcError::OAuthError.into());
            };

        if let Some(code) = code {
            Ok(handle_oauth_callback(jar, code, state, auth, &cache, store)
                .await
                .map_err(|_| OidcError::OAuthError)?
                .into_response())
        } else if let Some(error) = error {
            return Ok(
                Redirect::to(format!("{}?error={}", &auth.login_url, error).as_str())
                    .into_response(),
            );
        } else {
            // The OIDC provider did not provide error information
            return Err(OidcError::OAuthError.into());
        }
    }

    fn add_session_header(request: &mut Request<Body>, session: String) {
        let mutable_header = request.headers_mut();

        mutable_header.insert(
            "Authorization",
            HeaderValue::from_str(format!("Bearer {}", session).as_str()).unwrap(),
        );
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

impl<S, T: TSessionStore + 'static, C: TCache + 'static> Service<Request>
    for OpenIdConnectService<S, T, C>
where
    S::Future: Send + 'static,
    S::Error: Into<BoxError> + Send,
    S: Service<Request, Response = Response> + Clone + Send + 'static,
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

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let auth = self.oidc_config.clone();
        let store = self.store.clone();
        let cache = self.cache.clone();

        Box::pin(async move {
            let jar = CookieJar::from_headers(request.headers());
            let session_id_from_cookie = jar.get(SESSION_KEY).map(|c| c.value());
            let path = Some(request.uri().path().to_string());

            // Check if the session exists and if so redirect to the destination directly.
            if let Some(id) = session_id_from_cookie {
                let session_result = store.get(id).await?;

                if let Some(session) = session_result {
                    if let Some(v) = &path {
                        if *v == auth.logout_url && request.method() == Method::POST {
                            Self::handle_logout(session, &auth, cache).await?;
                            return Ok(Redirect::to("/").into_response());
                        }
                    }

                    Self::add_session_header(&mut request, session.id_token);
                    return inner.call(request).await.map_err(Into::into);
                }
            }

            // Handle unprotected paths required for successful authentication
            if let Some(path) = &path {
                let method = request.method();

                // No session exists yet, so force a redirect to the login page
                if *path == auth.login_url {
                    // Perform OIDC authentication
                    if method == Method::POST {
                        return Ok(handle_login_request(&auth, &jar, &cache)
                            .await
                            .map_err(|_| OidcError::OAuthError)?
                            .into_response());
                    }

                    // Forward to downstream login page
                    if method == Method::GET {
                        return inner.call(request).await.map_err(Into::into);
                    }

                // Handle the request form the OIDC provider after authentication
                } else if *path == auth.callback_url {
                    return Self::handle_oidc_callback(&auth, cache, &jar, request.uri(), &store).await;
                } else if *path == auth.logout_url {
                    // No session exists to be logged out. Redirect to home
                    return Ok(Redirect::to("/").into_response());
                } else {
                    return Ok(Redirect::to(&auth.login_url).into_response());
                }
            }

            inner.call(request).await.map_err(Into::into)
        })
    }
}
