use umbra_system::{api, db, scraper, service::UmbraService, mock_factory}; // Use library crate modules

use axum::{
    routing::{get, post},
    Router,
    middleware::{self, Next},
    http::Request,
    response::Response,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "umbra_system=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db = db::Db::new("sqlite:umbra.db?mode=rwc").await?;

    let scraper_rpc_url = "http://127.0.0.1:8899".to_string();
    let scraper_db = db.clone();
    tokio::spawn(async move {
        scraper::start_scraper(scraper_rpc_url, scraper_db).await;
    });



    let service = Arc::new(UmbraService::new("http://127.0.0.1:8899", db));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(api::health_check))
        .route("/api/status", get(api::system_status))
        .route("/relay", post(api::relay_handler))
        .route("/api/send", post(api::send_handler))
        .route("/api/inbox", get(api::inbox_handler))
        .route("/sync", get(api::sync_handler))
        .route("/claim", post(api::mark_claimed_handler))
        .route("/api/dev/seed", post(api::seed_handler))
        .layer(middleware::from_fn(remove_ip_headers))
        .layer(cors)
        .with_state(service);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    tracing::info!("listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    
    Ok(())
}

async fn remove_ip_headers(req: Request<axum::body::Body>, next: Next) -> Response {
    let mut req = req;
    let headers = req.headers_mut();
    
    // Strip common IP-tracking headers
    headers.remove("X-Forwarded-For");
    headers.remove("X-Real-IP");
    headers.remove("CF-Connecting-IP");
    headers.remove("True-Client-IP");
    
    next.run(req).await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("signal received, starting graceful shutdown");
}
