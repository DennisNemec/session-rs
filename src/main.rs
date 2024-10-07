use app::App;
use cache::RedisCache;
use claims::InMemoryClaimService;
use oauth::{routes::oauth_routes, OAuth};
use session::{SessionFactory, InMemorySessionService};

pub mod app;
pub mod cache;
pub mod claims;
pub mod oauth;
pub mod session;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cache = RedisCache::try_new("redis://localhost:6379")
        .unwrap_or_else(|e| panic!("Failed to connect to redis: {e:?}"));
    let session = InMemorySessionService::new();
    let factory = SessionFactory::new();
    let claim = InMemoryClaimService::new();
    let auth = OAuth::new(
        String::from("value"),
        String::from("value"),
        String::from("value"),
        String::from("value"),
        String::from("value"),
        vec![],
    );

    let _ = App::run("localhost", 8000, cache, session, factory, claim, oauth_routes().await).await;

    Ok(())
}
