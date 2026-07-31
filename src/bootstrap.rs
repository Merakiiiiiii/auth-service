use crate::{
    application::{
        AccessTokenPort, AuthApplication, AuthPolicy, AuthRepository, HealthProbe, PasswordPort,
        SecretPort,
    },
    config::Config,
    infrastructure::{
        ArgonPasswordAdapter, Ed25519TokenAdapter, PgAuthRepository, Sha256SecretAdapter,
    },
    transport::{GrpcAuthService, InternalGrpcAuth, http_router},
};
use platform_proto::auth_service_server::AuthServiceServer;
use std::{error::Error, sync::Arc};
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tracing::info;

pub type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub async fn run() -> AppResult<()> {
    load_environment();
    init_tracing();
    let config = Config::from_env().map_err(|error| send_sync_error(error.as_ref()))?;
    let repository = Arc::new(PgAuthRepository::connect(&config).await?);
    repository.ensure_schema().await?;
    let application = build_application(&config, repository.clone())?;
    let shutdown = shutdown_token();
    info!(
        grpc_address = %config.grpc_address,
        http_address = %config.http_address,
        "auth service started"
    );
    tokio::try_join!(
        serve_grpc(&config, application, shutdown.clone()),
        serve_http(&config, repository, shutdown),
    )?;
    Ok(())
}

fn load_environment() {
    dotenvy::from_filename(".env.local").ok();
    dotenvy::dotenv().ok();
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
}

fn build_application(
    config: &Config,
    repository: Arc<PgAuthRepository>,
) -> AppResult<Arc<AuthApplication>> {
    let repository: Arc<dyn AuthRepository> = repository;
    let passwords: Arc<dyn PasswordPort> = Arc::new(ArgonPasswordAdapter);
    let tokens: Arc<dyn AccessTokenPort> = Arc::new(
        Ed25519TokenAdapter::from_config(config)
            .map_err(|error| send_sync_error(error.as_ref()))?,
    );
    let secrets: Arc<dyn SecretPort> = Arc::new(Sha256SecretAdapter);
    let policy = AuthPolicy {
        access_ttl: config.access_ttl,
        refresh_ttl: config.refresh_ttl,
        verification_ttl: config.verification_ttl,
        reset_ttl: config.reset_ttl,
        email_change_ttl: config.email_change_ttl,
        lockout_threshold: config.lockout_threshold,
        lockout_duration: config.lockout_duration,
        log_sensitive_tokens: config.log_sensitive_tokens,
    };
    Ok(Arc::new(AuthApplication::new(
        repository, passwords, tokens, secrets, policy,
    )))
}

fn shutdown_token() -> CancellationToken {
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        signal.cancel();
    });
    shutdown
}

async fn serve_grpc(
    config: &Config,
    application: Arc<AuthApplication>,
    shutdown: CancellationToken,
) -> AppResult<()> {
    let service = GrpcAuthService::new(application);
    let service = AuthServiceServer::with_interceptor(
        service,
        InternalGrpcAuth::new(config.internal_grpc_token.clone()),
    );
    let (reporter, health) = tonic_health::server::health_reporter();
    reporter
        .set_serving::<AuthServiceServer<GrpcAuthService>>()
        .await;
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(platform_proto::FILE_DESCRIPTOR_SET)
        .build_v1()?;
    Server::builder()
        .add_service(health)
        .add_service(reflection)
        .add_service(service)
        .serve_with_shutdown(config.grpc_address, shutdown.cancelled_owned())
        .await?;
    Ok(())
}

async fn serve_http(
    config: &Config,
    health: Arc<dyn HealthProbe>,
    shutdown: CancellationToken,
) -> AppResult<()> {
    let listener = tokio::net::TcpListener::bind(config.http_address).await?;
    axum::serve(listener, http_router(health))
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await?;
    Ok(())
}

fn send_sync_error(error: &dyn Error) -> Box<dyn Error + Send + Sync> {
    error.to_string().into()
}
