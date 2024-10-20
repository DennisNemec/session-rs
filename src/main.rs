use app::App;

pub mod app;
pub mod builder;
pub mod cache;
pub mod oidc;
pub mod reverse_proxy;
pub mod session;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let gateway = App::new_from_cfg_file("api.yml").await.expect("OH NO");

    gateway.run().await;

    Ok(())
}
