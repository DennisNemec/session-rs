#![forbid(unsafe_code)]

use app::App;
use cache::RedisCache;
use modules::auth::oidc::OidcConfiguration;

pub mod app;
pub mod cache;
pub mod modules;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let auth = OidcConfiguration::new(
        "https://accounts.google.com",
        "<ID>",
        "<SECRET>",
        "http://localhost:8080/auth/callback",
        "/auth/callback",
        "/login",
        RedisCache::try_new("redis://localhost:6379").expect("Could not build redis cache"),
    )
    .await
    .unwrap();

    let _ = App::run("localhost", 8080, auth, "localhost:8081").await;

    Ok(())
}
