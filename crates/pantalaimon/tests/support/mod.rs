// Shared support code for the real-homeserver integration tests
// (tests/key_exchange_test.rs). Unlike proxy_test.rs, these tests drive two
// independent PanClient/OlmMachine identities against a real, containerized
// Matrix homeserver (see scripts/testing/homeserver.sh) instead of a
// wiremock stand-in, so real Olm/Megolm key exchange and SAS verification
// actually happen over the wire.
#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{atomic::{AtomicU32, Ordering}, Arc},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use pantalaimon::{
    client::PanClient,
    config::ServerConfig,
    messages::DaemonToUi,
    proxy::{build_router, daemon::ProxyDaemon},
    store::PanStore,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tower::ServiceExt;
use url::Url;

/// Must match the token `scripts/testing/homeserver.sh up` guarantees is
/// valid on the running continuwuity instance.
pub const REGISTRATION_TOKEN: &str = "pantalaimon-test-token";

pub fn homeserver_base_url() -> String {
    std::env::var("PANTALAIMON_TEST_HOMESERVER").unwrap_or_else(|_| "http://localhost:8008".to_owned())
}

/// Panics with a clear, actionable message if the real test homeserver isn't
/// reachable, instead of letting every subsequent HTTP call fail with a
/// confusing connection-refused error.
pub async fn require_real_homeserver() {
    let url = format!("{}/_matrix/client/versions", homeserver_base_url());
    let client = reqwest::Client::builder().timeout(Duration::from_secs(3)).build().unwrap();
    let ok = client.get(&url).send().await.map(|r| r.status().is_success()).unwrap_or(false);
    assert!(
        ok,
        "real homeserver not reachable at {url} — run `./scripts/testing/homeserver.sh up` first \
         (see docs/testing.md)"
    );
}

#[derive(Clone)]
pub struct RegisteredUser {
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
    pub username: String,
    pub password: String,
}

/// Register a fresh user on the real homeserver with a per-process-unique
/// username (so repeated runs against the same persistent volume never
/// collide), using the static registration token that `homeserver.sh up`
/// guarantees is valid.
pub async fn register_user(base_url: &str, name_prefix: &str) -> RegisteredUser {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let username = format!("{name_prefix}-{}-{millis}-{n}", std::process::id());
    let password = "test-password-does-not-matter".to_owned();

    let client = reqwest::Client::new();

    let init: Value = client
        .post(format!("{base_url}/_matrix/client/v3/register"))
        .json(&json!({ "username": username, "password": password, "inhibit_login": true }))
        .send()
        .await
        .expect("register step 1 request")
        .json()
        .await
        .expect("register step 1 body");
    let session = init["session"].as_str().expect("registration session id").to_owned();

    let resp: Value = client
        .post(format!("{base_url}/_matrix/client/v3/register"))
        .json(&json!({
            "username": username,
            "password": password,
            "auth": {
                "type": "m.login.registration_token",
                "token": REGISTRATION_TOKEN,
                "session": session,
            },
            "inhibit_login": false,
        }))
        .send()
        .await
        .expect("register step 2 request")
        .json()
        .await
        .expect("register step 2 body");

    RegisteredUser {
        user_id: resp["user_id"].as_str().expect("user_id in register response").to_owned(),
        device_id: resp["device_id"].as_str().expect("device_id in register response").to_owned(),
        access_token: resp["access_token"]
            .as_str()
            .expect("access_token in register response")
            .to_owned(),
        username,
        password,
    }
}

fn server_conf(base_url: &str, ignore_verification: bool) -> ServerConfig {
    ServerConfig {
        name: "test".to_owned(),
        homeserver: Url::parse(base_url).unwrap(),
        listen_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        listen_port: 8009,
        proxy: None,
        ssl: false,
        ignore_verification,
        use_keyring: false,
        search_requests: false,
        index_encrypted_only: false,
        indexing_batch_size: 100,
        history_fetch_delay: 3.0,
        drop_old_keys: false,
    }
}

/// One "party" in a real-homeserver test: a ProxyDaemon + router for a
/// single logged-in user, plus the `DaemonToUi` receiver that user's
/// PanClient emits signals on.
pub struct TestParty {
    pub router: axum::Router,
    pub daemon: Arc<ProxyDaemon>,
    pub user: RegisteredUser,
    pub ui_rx: mpsc::Receiver<DaemonToUi>,
    _store: Arc<PanStore>,
    _dir: TempDir,
}

/// Build a ProxyDaemon+router pointed at the real homeserver, and log the
/// given registered user in *through the router* (mirroring what a real
/// Matrix client does), so `daemon.pan_clients` gets populated the same way
/// production traffic would populate it.
pub async fn build_party(base_url: &str, ignore_verification: bool, mut user: RegisteredUser) -> TestParty {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(PanStore::new(dir.path()).await.unwrap());
    let (ui_tx, ui_rx) = mpsc::channel(64);
    let daemon = ProxyDaemon::new(
        server_conf(base_url, ignore_verification),
        store.clone(),
        dir.path().to_path_buf(),
        Some(ui_tx),
    )
    .await
    .unwrap();
    let router = build_router(daemon.clone());

    let login_req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": user.username },
                "password": user.password,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = router.clone().oneshot(login_req).await.unwrap();
    assert_eq!(resp.status(), 200, "login through proxy must succeed");
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let login_body: Value = serde_json::from_slice(&bytes).unwrap();

    // The password login above creates its own session, distinct from the
    // one `register_user` obtained at registration time (different
    // device_id, different access_token) — the PanClient/OlmMachine the
    // router just created only exists for *this* session. Overwrite `user`
    // with the live session's identifiers so callers never accidentally
    // reference the registration-time device that has no crypto state.
    user.device_id = login_body["device_id"].as_str().expect("device_id in login response").to_owned();
    user.access_token =
        login_body["access_token"].as_str().expect("access_token in login response").to_owned();

    TestParty { router, daemon, user, ui_rx, _store: store, _dir: dir }
}

impl TestParty {
    /// The live `PanClient` this party's login registered — the same
    /// instance the real HTTP routes use, so calling `handle_ui_command` /
    /// `run_post_sync_tasks` directly on it exercises real production code,
    /// just without the D-Bus transport in front of it.
    pub fn client(&self) -> Arc<PanClient> {
        self.daemon
            .pan_clients
            .get(&self.user.user_id)
            .expect("PanClient must be registered after login")
            .clone()
    }

    /// `GET /sync` through the router, then *directly* await
    /// `run_post_sync_tasks()` instead of relying on the fire-and-forget
    /// `tokio::spawn` the real sync route uses — otherwise key
    /// upload/query/claim and to-device delivery would race the test.
    pub async fn sync_and_settle(&self, since: Option<&str>) -> (Option<String>, Value) {
        let uri = match since {
            Some(s) => format!("/_matrix/client/v3/sync?since={s}&timeout=0"),
            None => "/_matrix/client/v3/sync?timeout=0".to_owned(),
        };
        let req = Request::builder()
            .uri(uri)
            .header("Authorization", format!("Bearer {}", self.user.access_token))
            .body(Body::empty())
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200, "sync must succeed");
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();

        self.client().run_post_sync_tasks().await;

        let next_batch = body.get("next_batch").and_then(|v| v.as_str()).map(String::from);
        (next_batch, body)
    }

    pub async fn put_json(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("PUT")
            .uri(path)
            .header("Authorization", format!("Bearer {}", self.user.access_token))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    pub async fn post_json(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("Authorization", format!("Bearer {}", self.user.access_token))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }
}

/// Non-blocking drain of every `DaemonToUi` signal currently queued.
pub fn drain_signals(rx: &mut mpsc::Receiver<DaemonToUi>) -> Vec<DaemonToUi> {
    let mut out = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        out.push(msg);
    }
    out
}

/// Create a private, E2E-encrypted room (via `creator`'s router) and invite
/// `invite_user_id`. Returns the new room_id.
pub async fn create_encrypted_room(creator: &TestParty, invite_user_id: &str) -> String {
    let (status, body) = creator
        .post_json(
            "/_matrix/client/v3/createRoom",
            json!({
                "preset": "private_chat",
                "invite": [invite_user_id],
                "initial_state": [{
                    "type": "m.room.encryption",
                    "state_key": "",
                    "content": { "algorithm": "m.megolm.v1.aes-sha2" },
                }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "createRoom failed: {body}");
    body["room_id"].as_str().expect("room_id in createRoom response").to_owned()
}

/// Join `room_id` via `party`'s router.
pub async fn join_room(party: &TestParty, room_id: &str) {
    let (status, body) =
        party.post_json(&format!("/_matrix/client/v3/rooms/{room_id}/join"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "join failed: {body}");
}

/// Send an `m.room.message` (text) into `room_id` via `party`'s router —
/// exercises the real `send_message` proxy handler, so for an encrypted
/// room this goes through `PanClient::prepare_and_encrypt` exactly as a
/// real client's send would.
pub async fn send_text(party: &TestParty, room_id: &str, txn: &str, body_text: &str) -> (StatusCode, Value) {
    party
        .put_json(
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}"),
            json!({ "msgtype": "m.text", "body": body_text }),
        )
        .await
}
