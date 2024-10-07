use app::App;
use cache::RedisCache;
use session::{SessionFactory, SessionService};

pub mod app;
pub mod cache;
pub mod claims;
pub mod gateway;
pub mod oauth;
pub mod session;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cache = RedisCache::try_new("redis://localhost:6379")
        .unwrap_or_else(|e| panic!("Failed to connect to redis: {e:?}"));
    let session = SessionService::new();
    let factory = SessionFactory::new();

    let _ = App::run("localhost", 8000, cache, session, factory).await;

    Ok(())
}
