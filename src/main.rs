mod application;
mod bootstrap;
mod config;
mod domain;
mod infrastructure;
mod transport;

#[tokio::main]
async fn main() -> bootstrap::AppResult<()> {
    bootstrap::run().await
}
