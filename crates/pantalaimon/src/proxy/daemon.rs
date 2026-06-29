use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use axum::{body::Body, extract::Request, response::Response};
use bytes::Bytes;
use dashmap::DashMap;
use http::header::HeaderName;
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, info, warn};

use tokio::sync::mpsc;

use crate::{
    client::PanClient,
    config::ServerConfig,
    error::AppError,
    messages::DaemonToUi,
    store::PanStore,
};

/// Headers that must not be forwarded between client ↔ proxy ↔ upstream.
static HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &HeaderName) -> bool {
    let s = name.as_str();
    HOP_BY_HOP.iter().any(|h| *h == s)
}

/// Shared state for one homeserver proxy instance (one per `[section]` in
/// the config).  Wrapped in `Arc` and used as axum `State`.
pub struct ProxyDaemon {
    pub name: String,
    pub server_conf: ServerConfig,
    pub store: Arc<PanStore>,
    pub data_dir: PathBuf,
    pub http_client: Client,
    /// Channel to forward daemon→UI signals from freshly-created PanClients.
    pub ui_tx: Option<mpsc::Sender<DaemonToUi>>,

    /// user_id → PanClient.  One client per logged-in user.
    pub pan_clients: DashMap<String, Arc<PanClient>>,

    /// access_token → user_id reverse-lookup so we can find a client from
    /// an arbitrary Bearer token without scanning pan_clients linearly.
    token_to_user: DashMap<String, String>,
}

impl ProxyDaemon {
    pub async fn new(
        server_conf: ServerConfig,
        store: Arc<PanStore>,
        data_dir: PathBuf,
        ui_tx: Option<mpsc::Sender<DaemonToUi>>,
    ) -> Result<Arc<Self>> {
        let mut client_builder = Client::builder();

        if let Some(proxy_url) = &server_conf.proxy {
            client_builder =
                client_builder.proxy(reqwest::Proxy::all(proxy_url.as_str())?);
        }

        if !server_conf.ssl {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        let http_client = client_builder.build()?;

        Ok(Arc::new(Self {
            name: server_conf.name.clone(),
            server_conf,
            store,
            data_dir,
            http_client,
            ui_tx,
            pan_clients: DashMap::new(),
            token_to_user: DashMap::new(),
        }))
    }

    // -----------------------------------------------------------------------
    // Client registry
    // -----------------------------------------------------------------------

    /// Register a freshly created (or restored) `PanClient`.
    ///
    /// If the same user_id already has a client, its old token mapping is
    /// removed so stale Bearer tokens stop resolving.
    pub fn register_client(&self, client: Arc<PanClient>) {
        let user_id = client.user_id.clone();
        let token = client.access_token.clone();

        // Remove the old token → user_id entry so the old token stops working.
        if let Some(old) = self.pan_clients.get(&user_id) {
            self.token_to_user.remove(&old.access_token);
        }

        self.token_to_user.insert(token, user_id.clone());
        self.pan_clients.insert(user_id, client);
    }

    /// Return true if `token` belongs to a user we already track.
    pub fn is_known_token(&self, token: &str) -> bool {
        self.token_to_user.contains_key(token)
    }

    /// Find the `PanClient` that owns `token`.
    ///
    /// Fast path: `token_to_user` cache hit → O(1) lookup.
    /// Slow path: call `/_matrix/client/v3/whoami` to resolve the token.
    /// If the token is valid but no PanClient exists (e.g. daemon restarted
    /// and ement resumed with its stored token without a fresh login), a
    /// PanClient is created on the fly and the session is persisted so the
    /// next restart finds it without needing whoami.
    pub async fn resolve_client(&self, token: &str) -> Option<Arc<PanClient>> {
        // Fast path
        if let Some(user_id) = self.token_to_user.get(token) {
            return self.pan_clients.get(user_id.as_str()).map(|r| r.clone());
        }

        // Slow path: ask the homeserver who this token belongs to.
        #[derive(Deserialize)]
        struct WhoamiResp {
            user_id: String,
            device_id: Option<String>,
        }

        let base = self.server_conf.homeserver.as_str().trim_end_matches('/');
        let url = format!("{base}/_matrix/client/v3/whoami");

        let resp = self
            .http_client
            .get(&url)
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            return None;
        }

        let whoami: WhoamiResp = resp.json().await.ok()?;
        let user_id = whoami.user_id;
        let device_id = whoami.device_id.unwrap_or_else(|| "UNKNOWN".to_owned());

        // Cache the token → user_id mapping for future requests.
        self.token_to_user.insert(token.to_owned(), user_id.clone());

        // If a PanClient already exists (restored from DB at startup), return it.
        if let Some(client) = self.pan_clients.get(&user_id) {
            return Some(client.clone());
        }

        // No PanClient yet — the user has a valid token but this daemon
        // instance never intercepted their login (e.g. daemon restarted and
        // ement reused its stored token).  Create a client on the fly so
        // crypto works immediately, and persist the session so the next
        // restart restores it properly without this whoami call.
        info!(%user_id, %device_id, "auto-creating PanClient for resumed session");

        if let Err(e) = self.store.save_access_token(&user_id, &device_id, token).await {
            warn!(%user_id, "save_access_token: {e}");
        }
        if let Err(e) = self.store.save_server_user(&self.name, &user_id).await {
            warn!(%user_id, "save_server_user: {e}");
        }

        match crate::client::PanClient::new(
            user_id.clone(),
            device_id,
            token.to_owned(),
            self.server_conf.clone(),
            self.store.clone(),
            &self.data_dir,
            self.http_client.clone(),
            self.ui_tx.clone(),
        )
        .await
        {
            Ok(client) => {
                let client = Arc::new(client);
                client.clone().start_sync().await;
                self.register_client(client.clone());
                Some(client)
            }
            Err(e) => {
                warn!(%user_id, "auto-create PanClient failed: {e}");
                None
            }
        }
    }

    // -----------------------------------------------------------------------
    // HTTP proxy
    // -----------------------------------------------------------------------

    /// Transparently forward `req` to the configured homeserver.
    pub async fn forward_request(&self, req: Request) -> Result<Response, AppError> {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();

        let path_and_query = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("");

        let base = self
            .server_conf
            .homeserver
            .as_str()
            .trim_end_matches('/');
        let upstream_url = format!("{base}{path_and_query}");

        debug!("{method} {upstream_url}");

        let mut req_builder = self.http_client.request(method, &upstream_url);

        for (name, value) in &headers {
            if !is_hop_by_hop(name) && name != "host" {
                req_builder = req_builder.header(name.clone(), value.clone());
            }
        }

        // 100 MiB hard limit on request body — matches the Python daemon.
        let body_bytes: Bytes = axum::body::to_bytes(req.into_body(), 100 * 1024 * 1024)
            .await
            .map_err(|_| AppError::Body)?;

        if !body_bytes.is_empty() {
            req_builder = req_builder.body(body_bytes);
        }

        let upstream_resp = req_builder.send().await?;

        let status = upstream_resp.status();
        let resp_headers = upstream_resp.headers().clone();
        let resp_bytes = upstream_resp.bytes().await?;

        let mut builder = Response::builder().status(status);
        for (name, value) in &resp_headers {
            if !is_hop_by_hop(name) {
                builder = builder.header(name.clone(), value.clone());
            }
        }

        Ok(builder.body(Body::from(resp_bytes)).unwrap())
    }
}
