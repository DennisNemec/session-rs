use std::str::FromStr;

use axum::{
    extract::Request,
    http::{HeaderValue, Uri},
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use reqwest::StatusCode;
use tower::{BoxError, Layer, Service};

use super::{is_prefix, PathDefinition};

#[derive(Clone)]
pub struct ReverseProxyLayer {
    path_definitions: Vec<PathDefinition>,
    fallback_path: Option<PathDefinition>,
}

impl ReverseProxyLayer {
    pub fn new(path_definitions: Vec<PathDefinition>) -> Self {
        let fallback_path = path_definitions
            .iter()
            .filter(|f| &f.path == "/")
            .cloned()
            .collect::<Vec<PathDefinition>>();

        Self {
            path_definitions,
            fallback_path: if fallback_path.is_empty() {
                None
            } else {
                Some(fallback_path[0].clone())
            },
        }
    }
}

impl<S> Layer<S> for ReverseProxyLayer {
    type Service = ReverseProxyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ReverseProxyService::new(
            inner,
            self.path_definitions.clone(),
            self.fallback_path.clone(),
        )
    }
}

#[derive(Clone)]
pub struct ReverseProxyService<S> {
    inner: S,
    path_definitions: Vec<PathDefinition>,
    fallback_path: Option<PathDefinition>,
}

impl<S> ReverseProxyService<S> {
    pub fn new(
        inner: S,
        path_definitions: Vec<PathDefinition>,
        fallback_path: Option<PathDefinition>,
    ) -> Self {
        Self {
            path_definitions,
            inner,
            fallback_path,
        }
    }

    pub fn get_definition_by_path(&self, path: String) -> Option<PathDefinition> {
        let paths: Vec<PathDefinition> = self
            .path_definitions
            .clone()
            .into_iter()
            .filter(|def| is_prefix(&def.path, &path))
            .collect();

        if !paths.is_empty() {
            return Some(paths[0].clone());
        } else {
            if self.fallback_path.is_some() {
                return self.fallback_path.clone();
            }
        }

        None
    }

    pub fn modify_request(&self, mut request: Request, path: &PathDefinition) -> Request {
        let is_fallback = &path.path == "/";

        let headers = request.headers_mut();
        *headers.get_mut("host").unwrap() = HeaderValue::from_str(&path.dst_addr).unwrap();

        if let Some(protected) = path.protected {
            headers.insert("X-protected", protected.to_string().parse().unwrap());
        }

        if !is_fallback {
            let uri = request.uri_mut();
            let replaced_uri = Uri::from_str(
                uri.to_string()
                    .replace(&path.path[1..path.path.len()], "")
                    .as_str(),
            )
            .unwrap();

            *uri = replaced_uri;
        }

        request
    }
}

impl<S> Service<Request> for ReverseProxyService<S>
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

    fn call(&mut self, mut req: Request) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let _definitions = self.path_definitions.clone();
        let s = self.clone();

        Box::pin(async move {
            let current_uri = req.uri_mut().to_string();
            let path_definition = s.get_definition_by_path(current_uri.clone());

            if path_definition.is_none() {
                return Ok(StatusCode::NOT_FOUND.into_response());
            }

            let modified_req = s.modify_request(req, &path_definition.unwrap());

            inner.call(modified_req).await.map_err(Into::into)
        })
    }
}
