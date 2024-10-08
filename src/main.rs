#![forbid(unsafe_code)]

use app::App;
use cache::RedisCache;
use modules::auth::{
    claims::InMemoryClaimService,
    oauth::{google::GooglePersonEndpoint, routes::oauth_routes, OAuth, OAuthState},
    session::InMemorySessionService,
};

pub mod app;
pub mod cache;
pub mod modules;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cache = RedisCache::try_new("redis://localhost:6379").expect("Failed to connect to redis: {e:?}");
    let mut session = InMemorySessionService::new();
    let mut claim = InMemoryClaimService::new();

    // TEST DATA
    claim.add_claim("d504295f-b9d9-4742-bd19-842ae87906ce", "{}");
    claim.add_claim("Dennis.nemec98@gmail.com", "{}");
    session.session_add(
        "session:d504295f-aaaa-bbbb-cccc-842ae87906ca",
        "d504295f-b9d9-4742-bd19-842ae87906ce",
    );

    let auth = OAuth::new(
        String::from("CLIENT_ID"),
        String::from("CLIENT_SECRET"),
        String::from("https://accounts.google.com/o/oauth2/auth"),
        String::from("https://oauth2.googleapis.com/token"),
        String::from("http://localhost:8080/auth/callback"),
        vec![
            String::from("https://www.googleapis.com/auth/userinfo.email"),
            String::from("https://www.googleapis.com/auth/userinfo.profile"),
        ],
        GooglePersonEndpoint::new(vec!["names", "emailAddresses"]),
    );

    let state = OAuthState::new(cache, session, claim, auth);

    let _ = App::run("localhost", 8080, oauth_routes(state)).await;

    Ok(())
}
