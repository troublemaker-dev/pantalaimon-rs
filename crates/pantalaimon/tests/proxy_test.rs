// Integration tests for the proxy route handlers.
//
// Each test spins up a `wiremock::MockServer` to stand in for the homeserver
// and drives the axum router via `tower::ServiceExt::oneshot`.

use std::{net::{IpAddr, Ipv4Addr}, sync::Arc};

use axum::{body::{to_bytes, Body}, http::Request};
use pantalaimon::{
    config::ServerConfig,
    proxy::{build_router, daemon::ProxyDaemon},
    store::PanStore,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;
use url::Url;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

// ─── Test infrastructure ──────────────────────────────────────────────────────

fn server_conf(homeserver_url: &str) -> ServerConfig {
    ServerConfig {
        name: "test".to_owned(),
        homeserver: Url::parse(homeserver_url).unwrap(),
        listen_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        listen_port: 8009,
        proxy: None,
        ssl: false,
        ignore_verification: false,
        use_keyring: false,
        search_requests: false,
        index_encrypted_only: false,
        indexing_batch_size: 100,
        history_fetch_delay: 3.0,
        drop_old_keys: false,
    }
}

async fn make_router(mock: &MockServer) -> (axum::Router, Arc<PanStore>, TempDir) {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(PanStore::new(dir.path()).await.unwrap());
    let daemon =
        ProxyDaemon::new(server_conf(&mock.uri()), store.clone(), dir.path().to_path_buf(), None)
            .await
            .unwrap();
    (build_router(daemon), store, dir)
}

/// Mount permissive mocks for OlmMachine background requests (key upload/query).
/// These aren't the subject of any assertion — they just prevent log noise.
async fn mount_crypto_noise(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/_matrix/client/v3/keys/upload"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"one_time_key_counts": {}})),
        )
        .mount(mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/_matrix/client/v3/keys/query"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"device_keys": {}})),
        )
        .mount(mock)
        .await;
}

fn login_json() -> Value {
    json!({
        "user_id": "@alice:localhost",
        "device_id": "DEVICE1",
        "access_token": "syt_test_token",
        "home_server": "localhost"
    })
}

fn basic_sync_json() -> Value {
    json!({
        "next_batch": "s2",
        "rooms": {"join": {}, "leave": {}, "invite": {}},
        "to_device": {"events": []},
        "device_lists": {"changed": [], "left": []},
        "device_one_time_keys_count": {}
    })
}

/// Perform a login through the proxy and return the router for further use.
/// Mounts the required homeserver stub on `mock`.
async fn do_login(router: axum::Router, mock: &MockServer) -> axum::Router {
    Mock::given(method("POST"))
        .and(path("/_matrix/client/v3/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_json()))
        .mount(mock)
        .await;

    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/login")
        .header("content-type", "application/json")
        .body(Body::from(json!({"type": "m.login.password", "password": "pw"}).to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200, "login should succeed");
    router
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// Unrecognised paths fall through to the homeserver unchanged.
#[tokio::test]
async fn test_fallback_proxies_unknown_route() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/some/custom/endpoint"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .mount(&mock)
        .await;

    let (router, _store, _dir) = make_router(&mock).await;
    let req = Request::builder().uri("/some/custom/endpoint").body(Body::empty()).unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], b"pong");
}

/// Successful login is forwarded, the client is registered, and subsequent
/// incremental syncs with the token are processed rather than just proxied.
#[tokio::test]
async fn test_login_success_registers_client() {
    let mock = MockServer::start().await;
    mount_crypto_noise(&mock).await;

    let (router, _store, _dir) = make_router(&mock).await;
    let router = do_login(router, &mock).await;

    Mock::given(method("GET"))
        .and(path("/_matrix/client/v3/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(basic_sync_json()))
        .mount(&mock)
        .await;

    let req = Request::builder()
        .uri("/_matrix/client/v3/sync?since=s1&timeout=0")
        .header("Authorization", "Bearer syt_test_token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    // process_sync ran and preserved next_batch
    assert_eq!(body["next_batch"], "s2");
}

/// A non-2xx homeserver response on login is forwarded as-is.
#[tokio::test]
async fn test_login_upstream_failure_forwarded() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/_matrix/client/v3/login"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"errcode": "M_FORBIDDEN", "error": "Bad password"})),
        )
        .mount(&mock)
        .await;

    let (router, _store, _dir) = make_router(&mock).await;
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/login")
        .header("content-type", "application/json")
        .body(Body::from(json!({"password": "wrong"}).to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = body_json(resp).await;
    assert_eq!(body["errcode"], "M_FORBIDDEN");
}

/// The r0 login route behaves identically to v3.
#[tokio::test]
async fn test_login_r0_route_works() {
    let mock = MockServer::start().await;
    mount_crypto_noise(&mock).await;
    Mock::given(method("POST"))
        .and(path("/_matrix/client/r0/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_json()))
        .mount(&mock)
        .await;

    let (router, _store, _dir) = make_router(&mock).await;
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/r0/login")
        .header("content-type", "application/json")
        .body(Body::from(json!({"type": "m.login.password", "password": "pw"}).to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

/// Initial sync (no `since`) is proxy-passed directly without buffering/processing.
#[tokio::test]
async fn test_sync_initial_is_proxied_directly() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_matrix/client/v3/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(basic_sync_json()))
        .mount(&mock)
        .await;

    let (router, _store, _dir) = make_router(&mock).await;
    // No `since` → initial sync
    let req = Request::builder()
        .uri("/_matrix/client/v3/sync?timeout=30000")
        .header("Authorization", "Bearer any_token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["next_batch"], "s2");
}

/// Incremental sync with an unknown token is forwarded without crypto processing.
#[tokio::test]
async fn test_sync_incremental_unknown_token_proxied() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_matrix/client/v3/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(basic_sync_json()))
        .mount(&mock)
        .await;

    let (router, _store, _dir) = make_router(&mock).await;
    let req = Request::builder()
        .uri("/_matrix/client/v3/sync?since=s1&timeout=0")
        .header("Authorization", "Bearer unknown_tok")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

/// Incremental sync with a registered client runs `process_sync`.
#[tokio::test]
async fn test_sync_incremental_with_registered_client() {
    let mock = MockServer::start().await;
    mount_crypto_noise(&mock).await;

    let (router, _store, _dir) = make_router(&mock).await;
    let router = do_login(router, &mock).await;

    Mock::given(method("GET"))
        .and(path("/_matrix/client/v3/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(basic_sync_json()))
        .mount(&mock)
        .await;

    let req = Request::builder()
        .uri("/_matrix/client/v3/sync?since=s1&timeout=0")
        .header("Authorization", "Bearer syt_test_token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["next_batch"], "s2");
}

/// Send with no auth token is forwarded to the homeserver without encryption.
#[tokio::test]
async fn test_send_no_token_proxied() {
    let mock = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"event_id": "$ev:h"})))
        .mount(&mock)
        .await;

    let (router, _store, _dir) = make_router(&mock).await;
    let req = Request::builder()
        .method("PUT")
        .uri("/_matrix/client/v3/rooms/testroom/send/m.room.message/txn1")
        .header("content-type", "application/json")
        .body(Body::from(json!({"msgtype": "m.text", "body": "hi"}).to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

/// After login, sending to a non-encrypted room is forwarded as plaintext.
/// The proxy checks the room encryption state (404 → not encrypted) and
/// returns `SendOutcome::NotEncrypted`, so the original body passes through.
#[tokio::test]
async fn test_send_unencrypted_room_forwarded_plaintext() {
    let mock = MockServer::start().await;
    mount_crypto_noise(&mock).await;

    let (router, _store, _dir) = make_router(&mock).await;
    let router = do_login(router, &mock).await;

    // Room encryption state: 404 → not encrypted
    Mock::given(method("GET"))
        .and(path("/_matrix/client/v3/rooms/testroom/state/m.room.encryption"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"errcode": "M_NOT_FOUND"})),
        )
        .mount(&mock)
        .await;

    // Forwarded plaintext send
    Mock::given(method("PUT"))
        .and(path("/_matrix/client/v3/rooms/testroom/send/m.room.message/txn1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"event_id": "$ev1:h"})))
        .mount(&mock)
        .await;

    let req = Request::builder()
        .method("PUT")
        .uri("/_matrix/client/v3/rooms/testroom/send/m.room.message/txn1")
        .header("Authorization", "Bearer syt_test_token")
        .header("content-type", "application/json")
        .body(Body::from(json!({"msgtype": "m.text", "body": "hello"}).to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["event_id"], "$ev1:h");
}

/// Upload from an unknown token is forwarded unchanged (no AES encryption applied).
#[tokio::test]
async fn test_upload_unknown_token_not_encrypted() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/_matrix/media/v3/upload"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"content_uri": "mxc://h/abc"})),
        )
        .mount(&mock)
        .await;

    let (router, _store, _dir) = make_router(&mock).await;
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/media/v3/upload?filename=test.txt")
        .header("Authorization", "Bearer unknown")
        .header("content-type", "text/plain")
        .body(Body::from("hello world"))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["content_uri"], "mxc://h/abc");
}

/// Upload from a registered user encrypts the body (AES-256-CTR) and stores
/// the encryption keys in PanStore keyed by the returned mxc URI.
#[tokio::test]
async fn test_upload_known_token_stores_encryption_keys() {
    let mock = MockServer::start().await;
    mount_crypto_noise(&mock).await;

    let dir = TempDir::new().unwrap();
    let store = Arc::new(PanStore::new(dir.path()).await.unwrap());
    let daemon =
        ProxyDaemon::new(server_conf(&mock.uri()), store.clone(), dir.path().to_path_buf(), None)
            .await
            .unwrap();
    let router = build_router(daemon);
    let router = do_login(router, &mock).await;

    Mock::given(method("POST"))
        .and(path("/_matrix/media/v3/upload"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"content_uri": "mxc://localhost/xyz789"})),
        )
        .mount(&mock)
        .await;

    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/media/v3/upload?filename=secret.bin")
        .header("Authorization", "Bearer syt_test_token")
        .header("content-type", "application/octet-stream")
        .body(Body::from(b"secret content".to_vec()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let media = store.load_media("test", "localhost", "xyz789").await.unwrap();
    assert!(media.is_some(), "encryption keys must be stored after upload");
    let media = media.unwrap();
    assert!(!media.iv.is_empty(), "iv should be stored");
    assert!(media.hashes.is_object(), "hashes should be stored");
}

/// Download for media with no stored keys is proxied to the homeserver.
#[tokio::test]
async fn test_download_no_stored_keys_proxied() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_matrix/media/v3/download/matrix.org/abc123"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/octet-stream")
                .set_body_bytes(b"raw file bytes".to_vec()),
        )
        .mount(&mock)
        .await;

    let (router, _store, _dir) = make_router(&mock).await;
    let req = Request::builder()
        .uri("/_matrix/media/v3/download/matrix.org/abc123")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], b"raw file bytes");
}

/// Download, decrypt, and return the plaintext when keys are stored.
///
/// Uploads a file so the proxy encrypts it and stores the keys, then captures
/// the actual ciphertext that was forwarded to the mock homeserver during
/// upload, serves that ciphertext back on download, and verifies the proxy
/// decrypts it to the original plaintext.
#[tokio::test]
async fn test_download_stored_keys_decrypts() {
    let mock = MockServer::start().await;
    mount_crypto_noise(&mock).await;

    let dir = TempDir::new().unwrap();
    let store = Arc::new(PanStore::new(dir.path()).await.unwrap());
    let daemon =
        ProxyDaemon::new(server_conf(&mock.uri()), store.clone(), dir.path().to_path_buf(), None)
            .await
            .unwrap();
    let router = build_router(daemon);
    let router = do_login(router, &mock).await;

    let plaintext = b"decryption test content";

    // ── Step 1: upload — proxy encrypts body and forwards ciphertext ──────────
    Mock::given(method("POST"))
        .and(path("/_matrix/media/v3/upload"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"content_uri": "mxc://localhost/dec_test"})),
        )
        .mount(&mock)
        .await;

    let upload_req = Request::builder()
        .method("POST")
        .uri("/_matrix/media/v3/upload")
        .header("Authorization", "Bearer syt_test_token")
        .header("content-type", "application/octet-stream")
        .body(Body::from(plaintext.to_vec()))
        .unwrap();
    router.clone().oneshot(upload_req).await.unwrap();

    // ── Step 2: retrieve the actual ciphertext sent to the mock ───────────────
    // wiremock records all received requests; find the upload body.
    let received = mock.received_requests().await.unwrap();
    let ciphertext = received
        .iter()
        .find(|r| r.url.path().ends_with("/upload"))
        .map(|r| r.body.clone())
        .expect("proxy must have forwarded the upload to the mock homeserver");

    // ── Step 3: serve that same ciphertext back on download ───────────────────
    Mock::given(method("GET"))
        .and(path("/_matrix/media/v3/download/localhost/dec_test"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/octet-stream")
                .set_body_bytes(ciphertext),
        )
        .mount(&mock)
        .await;

    let dl_req = Request::builder()
        .uri("/_matrix/media/v3/download/localhost/dec_test")
        .body(Body::empty())
        .unwrap();
    let dl_resp = router.oneshot(dl_req).await.unwrap();
    assert_eq!(dl_resp.status(), 200);
    let dl_bytes = to_bytes(dl_resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&dl_bytes[..], plaintext, "downloaded bytes must equal the original plaintext");
}

/// Search returns M_NOT_FOUND when search_requests is false (default).
#[tokio::test]
async fn test_search_disabled_returns_404() {
    let mock = MockServer::start().await;
    let (router, _store, _dir) = make_router(&mock).await;
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/search")
        .header("content-type", "application/json")
        .body(Body::from(json!({"search_categories": {}}).to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 404);
    let body = body_json(resp).await;
    assert_eq!(body["errcode"], "M_NOT_FOUND");
}

/// When search_requests is enabled, the search endpoint is forwarded to the homeserver.
#[tokio::test]
async fn test_search_enabled_forwards_to_homeserver() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/_matrix/client/v3/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"search_categories": {}})))
        .mount(&mock)
        .await;

    let dir = TempDir::new().unwrap();
    let store = Arc::new(PanStore::new(dir.path()).await.unwrap());
    let mut conf = server_conf(&mock.uri());
    conf.search_requests = true;
    let daemon = ProxyDaemon::new(conf, store, dir.path().to_path_buf(), None).await.unwrap();
    let router = build_router(daemon);

    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/search")
        .header("content-type", "application/json")
        .body(Body::from(json!({"search_categories": {}}).to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

/// The /messages endpoint (paginated history) is forwarded and the response returned.
/// Encrypted events that can't be decrypted (no session) pass through as-is.
#[tokio::test]
async fn test_messages_endpoint_proxied() {
    let mock = MockServer::start().await;
    mount_crypto_noise(&mock).await;

    let (router, _store, _dir) = make_router(&mock).await;
    let router = do_login(router, &mock).await;

    Mock::given(method("GET"))
        .and(path("/_matrix/client/v3/rooms/!testroom:localhost/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "chunk": [
                {"type": "m.room.message", "content": {"msgtype": "m.text", "body": "hello"}, "event_id": "$e1:h"}
            ],
            "start": "t1",
            "end": "t2"
        })))
        .mount(&mock)
        .await;

    let req = Request::builder()
        .uri("/_matrix/client/v3/rooms/!testroom:localhost/messages?dir=b&limit=20")
        .header("Authorization", "Bearer syt_test_token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["chunk"][0]["type"], "m.room.message");
}

/// The r0 sync route behaves identically to v3.
#[tokio::test]
async fn test_sync_r0_route_works() {
    let mock = MockServer::start().await;
    mount_crypto_noise(&mock).await;

    let (router, _store, _dir) = make_router(&mock).await;
    let router = do_login(router, &mock).await;

    Mock::given(method("GET"))
        .and(path("/_matrix/client/r0/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(basic_sync_json()))
        .mount(&mock)
        .await;

    let req = Request::builder()
        .uri("/_matrix/client/r0/sync?since=s1&timeout=0")
        .header("Authorization", "Bearer syt_test_token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

/// IgnoreVerification flag is plumbed through to the server config.
#[tokio::test]
async fn test_ignore_verification_config_propagated() {
    let mock = MockServer::start().await;
    let dir = TempDir::new().unwrap();
    let store = Arc::new(PanStore::new(dir.path()).await.unwrap());
    let mut conf = server_conf(&mock.uri());
    conf.ignore_verification = true;
    let daemon =
        ProxyDaemon::new(conf.clone(), store, dir.path().to_path_buf(), None).await.unwrap();
    // Verify the flag is on the daemon's server config.
    assert!(daemon.server_conf.ignore_verification);
}

/// Download with a three-segment path (server/id/filename) resolves correctly.
#[tokio::test]
async fn test_download_with_filename_segment_proxied() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_matrix/media/v3/download/matrix.org/abc123/photo.jpg"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "image/jpeg")
                .set_body_bytes(b"jpeg data".to_vec()),
        )
        .mount(&mock)
        .await;

    let (router, _store, _dir) = make_router(&mock).await;
    let req = Request::builder()
        .uri("/_matrix/media/v3/download/matrix.org/abc123/photo.jpg")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], b"jpeg data");
}
