pub mod daemon;
pub mod routes;

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{routing::{get, post, put}, Router};

use crate::config::ServerConfig;

use self::{daemon::ProxyDaemon, routes::*};

/// Build the axum `Router` with all Matrix proxy routes.
pub fn build_router(daemon: Arc<ProxyDaemon>) -> Router {
    Router::new()
        // Login — GET returns available flows (proxy through); POST is intercepted
        .route("/_matrix/client/r0/login", get(proxy_pass).post(login))
        .route("/_matrix/client/v3/login", get(proxy_pass).post(login))
        // Sync
        .route("/_matrix/client/r0/sync", get(sync))
        .route("/_matrix/client/v3/sync", get(sync))
        // Create room
        .route("/_matrix/client/r0/createRoom", post(create_room))
        .route("/_matrix/client/v3/createRoom", post(create_room))
        // Paginated room history
        .route("/_matrix/client/r0/rooms/:room_id/messages", get(messages))
        .route("/_matrix/client/v3/rooms/:room_id/messages", get(messages))
        // Send event
        .route(
            "/_matrix/client/r0/rooms/:room_id/send/:event_type/:txnid",
            put(send_message),
        )
        .route(
            "/_matrix/client/v3/rooms/:room_id/send/:event_type/:txnid",
            put(send_message),
        )
        // Filter
        .route("/_matrix/client/r0/user/:user_id/filter", post(filter))
        .route("/_matrix/client/v3/user/:user_id/filter", post(filter))
        // Well-known
        .route("/.well-known/matrix/client", get(well_known).post(well_known))
        // Search
        .route("/_matrix/client/r0/search", post(search).options(search_opts))
        .route("/_matrix/client/v3/search", post(search).options(search_opts))
        // Media download (all versioned paths)
        .route(
            "/_matrix/media/v1/download/:server_name/:media_id",
            get(download),
        )
        .route(
            "/_matrix/media/v3/download/:server_name/:media_id",
            get(download),
        )
        .route(
            "/_matrix/media/v1/download/:server_name/:media_id/:file_name",
            get(download),
        )
        .route(
            "/_matrix/media/v3/download/:server_name/:media_id/:file_name",
            get(download),
        )
        .route(
            "/_matrix/media/r0/download/:server_name/:media_id",
            get(download),
        )
        .route(
            "/_matrix/media/r0/download/:server_name/:media_id/:file_name",
            get(download),
        )
        // Media upload
        .route("/_matrix/media/r0/upload", post(upload))
        .route("/_matrix/media/v3/upload", post(upload))
        // Profile — PUT sets avatar (intercepted for media key injection); GET proxies through
        .route(
            "/_matrix/client/r0/profile/:user_id/avatar_url",
            get(proxy_pass).put(profile),
        )
        .route(
            "/_matrix/client/v3/profile/:user_id/avatar_url",
            get(proxy_pass).put(profile),
        )
        // Catch-all
        .fallback(proxy_pass)
        .with_state(daemon)
}

/// Start listening for `server_conf` and serve requests via `daemon`.
pub async fn run(daemon: Arc<ProxyDaemon>, server_conf: ServerConfig) -> Result<()> {
    let addr = SocketAddr::new(server_conf.listen_address, server_conf.listen_port);
    let router = build_router(daemon);

    tracing::info!(
        "Proxy for {} listening on http://{}",
        server_conf.name,
        addr
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
