#![forbid(unsafe_code)]
use app::App;
use cache::RedisCache;
use dotenv::dotenv;
use oidc::controller::OidcConfiguration;
use session::{CachedSessionStore, SessionStore};

pub mod app;
pub mod cache;
pub mod oidc;
pub mod session;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let issuer_url =
        dotenv::var("OIDC_ISSUER_URL").expect("Could not find issuer url of the OIDC provider");
    let client_id = dotenv::var("OIDC_CLIENT_ID").expect("Could not find client id");
    let client_secret: String =
        dotenv::var("OIDC_CLIENT_SECRET").expect("Could not find client secret");
    let redirect_uri_host =
        dotenv::var("OIDC_REDIRECT_URI_HOST").expect("Could not find redirect URI");
    let auth_callback_path =
        dotenv::var("OIDC_AUTH_CALLBACK_PATH").expect("Could not find auth callback path");
    let login_path = dotenv::var("OIDC_LOGIN_PATH").expect("Could not find auth login path");
    let logout_path = dotenv::var("OIDC_LOGOUT_PATH").expect("Could not find auth logout path");
    let redis_url = dotenv::var("GATEWAY_REDIS_URI").expect("Could not find redis URI");
    let forward_address =
        dotenv::var("GATEWAY_FORWARD_ADDRESS").expect("Could not gateway forward address");
    let gateway_address = dotenv::var("GATEWAY_ADDRESS").expect("Could not find gateway address");
    let gateway_port = dotenv::var("GATEWAY_PORT").expect("Could not gateway port");

    let auth = OidcConfiguration::new(
        &issuer_url,
        &client_id,
        &client_secret,
        format!("{redirect_uri_host}{auth_callback_path}").as_str(),
        &auth_callback_path,
        &login_path,
        &logout_path,
    )
    .await
    .unwrap();

    let cache = RedisCache::try_new(&redis_url).expect("Could not build redis cache");
    let store = CachedSessionStore::new(cache.clone(), SessionStore::new("http://localhost:8082"));

    let _ = App::run(
        &gateway_address,
        gateway_port.parse().expect("Invalid gateway port"),
        auth,
        cache,
        store,
        &forward_address,
    )
    .await;

    Ok(())
}
