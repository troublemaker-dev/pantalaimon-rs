// Real key-exchange integration tests.
//
// Unlike proxy_test.rs (which mocks the homeserver with wiremock and only
// ever drives a single PanClient/OlmMachine), these tests stand up two
// independent PanClients against a REAL, containerized Matrix homeserver
// (continuwuity), so real Olm session establishment, Megolm room-key
// sharing, SAS device verification, and the unverified-device send-block
// flow are exercised end to end exactly as they'd happen in production.
//
// These are `#[ignore]`d so plain `cargo test` stays hermetic and never
// touches the network. Run them with:
//
//   ./scripts/testing/homeserver.sh up
//   cargo test --test key_exchange_test -- --ignored --nocapture
//
// See docs/testing.md for full setup instructions (Apple `container`,
// Docker, and Podman).

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use pantalaimon::messages::{DaemonToUi, UiToDaemon};
use support::*;
use tower::ServiceExt;

const MAX_ROUNDS: usize = 12;
const ROUND_DELAY: Duration = Duration::from_millis(300);

/// Real Olm/Megolm key exchange: alice sends an encrypted message and bob's
/// independent PanClient/OlmMachine actually decrypts it, having obtained
/// the room key via a real to-device relay through the homeserver.
#[tokio::test]
#[ignore = "requires a real homeserver: ./scripts/testing/homeserver.sh up"]
async fn test_real_key_exchange_encrypt_decrypt_roundtrip() {
    require_real_homeserver().await;
    let base = homeserver_base_url();

    let alice_user = register_user(&base, "alice").await;
    let bob_user = register_user(&base, "bob").await;
    let bob_user_id = bob_user.user_id.clone();

    let alice = build_party(&base, true, alice_user).await;
    let bob = build_party(&base, true, bob_user).await;

    // Initial syncs — no crypto processing happens here (see routes::sync's
    // is_initial_sync fast path), but run_post_sync_tasks still flushes each
    // party's own keys/upload so the other side can later claim a session.
    let (mut alice_since, _) = alice.sync_and_settle(None).await;
    let (mut bob_since, _) = bob.sync_and_settle(None).await;

    let room_id = create_encrypted_room(&alice, &bob_user_id).await;

    // Bob sees the invite and joins.
    let (next, _) = bob.sync_and_settle(bob_since.as_deref()).await;
    bob_since = next;
    join_room(&bob, &room_id).await;

    // Settle membership on both sides so device lists propagate (bob's join
    // needs to show up in alice's `device_lists.changed` before her OlmMachine
    // will have queried his device keys). The homeserver doesn't always
    // surface that on the very next sync, so poll until alice's OlmMachine
    // actually knows about a device for bob rather than assuming one round
    // is enough.
    let mut alice_knows_bob_device = false;
    for _ in 0..MAX_ROUNDS {
        let (next, _) = bob.sync_and_settle(bob_since.as_deref()).await;
        bob_since = next;
        let (next, _) = alice.sync_and_settle(alice_since.as_deref()).await;
        alice_since = next;

        if !alice.client().list_user_devices(&bob_user_id).await.is_empty() {
            alice_knows_bob_device = true;
            break;
        }
        tokio::time::sleep(ROUND_DELAY).await;
    }
    assert!(alice_knows_bob_device, "alice's OlmMachine must learn of bob's device before she can share a room key with him");

    let message = "hello bob, this is a real end-to-end encrypted message";
    let (status, body) = send_text(&alice, &room_id, "txn-roundtrip-1", message).await;
    assert_eq!(status, StatusCode::OK, "encrypted send must succeed: {body}");

    // Bob syncs (possibly more than once — real propagation isn't instant)
    // until he sees the decrypted message in the room timeline.
    let mut decrypted_body = None;
    for _ in 0..MAX_ROUNDS {
        let (next, body) = bob.sync_and_settle(bob_since.as_deref()).await;
        bob_since = next;

        if let Some(events) =
            body.pointer(&format!("/rooms/join/{room_id}/timeline/events")).and_then(|v| v.as_array())
        {
            for event in events {
                if event.get("type").and_then(|t| t.as_str()) == Some("m.room.message") {
                    decrypted_body = event.pointer("/content/body").and_then(|b| b.as_str()).map(String::from);
                }
            }
        }
        if decrypted_body.is_some() {
            break;
        }
        tokio::time::sleep(ROUND_DELAY).await;
    }

    let _ = alice_since; // only needed above; silence unused-assignment warning on the last write
    assert_eq!(
        decrypted_body.as_deref(),
        Some(message),
        "bob must receive and decrypt alice's real Megolm-encrypted message"
    );

    // Give reqwest's connection pool a chance to close its idle connections
    // gracefully before this test's tokio runtime is torn down, rather than
    // having them aborted mid-flight.
    drop(alice);
    drop(bob);
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// Full SAS emoji verification round trip between two independent
/// PanClients, driven the same way `message_router` drives it in
/// production — via `PanClient::handle_ui_command` — just without the
/// D-Bus transport in front of it.
#[tokio::test]
#[ignore = "requires a real homeserver: ./scripts/testing/homeserver.sh up"]
async fn test_real_sas_verification_round_trip() {
    require_real_homeserver().await;
    let base = homeserver_base_url();

    let alice_user = register_user(&base, "alice-sas").await;
    let bob_user = register_user(&base, "bob-sas").await;

    let mut alice = build_party(&base, false, alice_user).await;
    let mut bob = build_party(&base, false, bob_user).await;

    // Must be read from the *live* session (build_party's own password
    // login), not the registration-time session — they're different
    // devices, and only the live one has a PanClient/OlmMachine behind it.
    let alice_uid = alice.user.user_id.clone();
    let alice_did = alice.user.device_id.clone();
    let bob_uid = bob.user.user_id.clone();
    let bob_did = bob.user.device_id.clone();

    let (mut alice_since, _) = alice.sync_and_settle(None).await;
    let (mut bob_since, _) = bob.sync_and_settle(None).await;

    // In real usage a verification target is almost always a device you
    // already know about (from a shared room, or an explicit "verify this
    // user" flow that itself does a keys/query first) — check_incoming_verifications
    // only recognises an incoming m.key.verification.request if the
    // OlmMachine can already resolve a VerificationRequest for the sender,
    // which in turn needs the sender's device data. Prime that here the same
    // way a real client's device-list UI would have already done.
    bob.client().list_user_devices(&alice_uid).await;

    // Alice starts SAS verification with bob's device.
    alice
        .client()
        .handle_ui_command(UiToDaemon::StartSas {
            message_id: "sas-start".into(),
            pan_user: alice_uid.clone(),
            user_id: bob_uid.clone(),
            device_id: bob_did.clone(),
        })
        .await;

    // Bob syncs until he sees the incoming SasInvite.
    let mut saw_invite = false;
    for _ in 0..MAX_ROUNDS {
        let (next, _) = bob.sync_and_settle(bob_since.as_deref()).await;
        bob_since = next;
        if drain_signals(&mut bob.ui_rx).iter().any(|e| {
            matches!(e, DaemonToUi::SasInvite { user_id, device_id, .. } if user_id == &alice_uid && device_id == &alice_did)
        }) {
            saw_invite = true;
            break;
        }
        tokio::time::sleep(ROUND_DELAY).await;
    }
    assert!(saw_invite, "bob must see alice's SasInvite");

    // Bob accepts — this sends m.key.verification.ready + .start.
    bob.client()
        .handle_ui_command(UiToDaemon::AcceptSas {
            message_id: "sas-accept".into(),
            pan_user: bob_uid.clone(),
            user_id: alice_uid.clone(),
            device_id: alice_did.clone(),
        })
        .await;

    // Sync both sides repeatedly until each has emoji ready (SasShow).
    let mut alice_emoji = None;
    let mut bob_emoji = None;
    for _ in 0..MAX_ROUNDS {
        let (next, _) = alice.sync_and_settle(alice_since.as_deref()).await;
        alice_since = next;
        let (next, _) = bob.sync_and_settle(bob_since.as_deref()).await;
        bob_since = next;

        for e in drain_signals(&mut alice.ui_rx) {
            if let DaemonToUi::SasShow { emoji, .. } = e {
                alice_emoji = Some(emoji);
            }
        }
        for e in drain_signals(&mut bob.ui_rx) {
            if let DaemonToUi::SasShow { emoji, .. } = e {
                bob_emoji = Some(emoji);
            }
        }
        if alice_emoji.is_some() && bob_emoji.is_some() {
            break;
        }
        tokio::time::sleep(ROUND_DELAY).await;
    }
    let alice_emoji = alice_emoji.expect("alice must see SasShow with emoji");
    let bob_emoji = bob_emoji.expect("bob must see SasShow with emoji");
    assert_eq!(alice_emoji, bob_emoji, "both sides must compute the same emoji sequence");

    // Both sides confirm the emoji match.
    alice
        .client()
        .handle_ui_command(UiToDaemon::ConfirmSas {
            message_id: "sas-confirm-a".into(),
            pan_user: alice_uid.clone(),
            user_id: bob_uid.clone(),
            device_id: bob_did.clone(),
        })
        .await;
    bob.client()
        .handle_ui_command(UiToDaemon::ConfirmSas {
            message_id: "sas-confirm-b".into(),
            pan_user: bob_uid.clone(),
            user_id: alice_uid.clone(),
            device_id: alice_did.clone(),
        })
        .await;

    // Sync until both sides see SasDone.
    let mut alice_done = false;
    let mut bob_done = false;
    for _ in 0..MAX_ROUNDS {
        let (next, _) = alice.sync_and_settle(alice_since.as_deref()).await;
        alice_since = next;
        let (next, _) = bob.sync_and_settle(bob_since.as_deref()).await;
        bob_since = next;

        if drain_signals(&mut alice.ui_rx).iter().any(|e| matches!(e, DaemonToUi::SasDone { .. })) {
            alice_done = true;
        }
        if drain_signals(&mut bob.ui_rx).iter().any(|e| matches!(e, DaemonToUi::SasDone { .. })) {
            bob_done = true;
        }
        if alice_done && bob_done {
            break;
        }
        tokio::time::sleep(ROUND_DELAY).await;
    }
    assert!(alice_done && bob_done, "SAS verification must complete (SasDone) on both sides");

    // Indirect proof the devices are now actually trusted: share a real
    // encrypted room and confirm alice's send is no longer blocked by the
    // unverified-devices gate (ignore_verification is false on both parties
    // in this test, so a still-unverified bob device would block this).
    let room_id = create_encrypted_room(&alice, &bob_uid).await;
    let (next, _) = bob.sync_and_settle(bob_since.as_deref()).await;
    bob_since = next;
    join_room(&bob, &room_id).await;
    let (next, _) = bob.sync_and_settle(bob_since.as_deref()).await;
    let _ = next;
    let (next, _) = alice.sync_and_settle(alice_since.as_deref()).await;
    let _ = next;

    let (status, body) = send_text(&alice, &room_id, "txn-post-verify-1", "now trusted").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "send into a shared room must succeed immediately post-verification, without hitting the unverified-devices gate: {body}"
    );
}

/// The unverified-device send-block flow: a send into a room with an
/// unverified device blocks, `UnverifiedDevices` is signalled, and the
/// send only proceeds (or is cancelled) once `SendAnyways`/`CancelSending`
/// is delivered via `handle_ui_command` — exactly the code path fixed by
/// "Fix silent failures in the unverified-device send-block flow".
#[tokio::test]
#[ignore = "requires a real homeserver: ./scripts/testing/homeserver.sh up"]
async fn test_real_unverified_device_send_block_flow() {
    require_real_homeserver().await;
    let base = homeserver_base_url();

    let alice_user = register_user(&base, "alice-block").await;
    let bob_user = register_user(&base, "bob-block").await;
    let bob_user_id = bob_user.user_id.clone();

    let mut alice = build_party(&base, false, alice_user).await;
    let bob = build_party(&base, false, bob_user).await;

    let (mut alice_since, _) = alice.sync_and_settle(None).await;
    let (mut bob_since, _) = bob.sync_and_settle(None).await;

    let room_id = create_encrypted_room(&alice, &bob_user_id).await;
    let (next, _) = bob.sync_and_settle(bob_since.as_deref()).await;
    bob_since = next;
    join_room(&bob, &room_id).await;

    // Poll until alice's OlmMachine actually knows about a device for bob —
    // otherwise has_unverified_devices() has nothing to find and the send
    // goes straight through instead of blocking (see the identical comment
    // in test_real_key_exchange_encrypt_decrypt_roundtrip).
    let mut alice_knows_bob_device = false;
    for _ in 0..MAX_ROUNDS {
        let (next, _) = bob.sync_and_settle(bob_since.as_deref()).await;
        bob_since = next;
        let (next, _) = alice.sync_and_settle(alice_since.as_deref()).await;
        alice_since = next;

        if !alice.client().list_user_devices(&bob_user_id).await.is_empty() {
            alice_knows_bob_device = true;
            break;
        }
        tokio::time::sleep(ROUND_DELAY).await;
    }
    assert!(alice_knows_bob_device, "alice's OlmMachine must learn of bob's device before the unverified-devices gate can trigger");
    let _ = alice_since;

    // --- SendAnyways case ---
    {
        let alice_router = alice.router.clone();
        let alice_token = alice.user.access_token.clone();
        let send_room_id = room_id.clone();
        let send_task = tokio::spawn(async move {
            let req = axum::http::Request::builder()
                .method("PUT")
                .uri(format!("/_matrix/client/v3/rooms/{send_room_id}/send/m.room.message/txn-block-anyways"))
                .header("Authorization", format!("Bearer {alice_token}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({ "msgtype": "m.text", "body": "send anyway?" }).to_string(),
                ))
                .unwrap();
            alice_router.oneshot(req).await.unwrap()
        });

        let signal = tokio::time::timeout(Duration::from_secs(15), alice.ui_rx.recv())
            .await
            .expect("UnverifiedDevices signal timed out")
            .expect("ui_rx channel closed unexpectedly");
        match &signal {
            DaemonToUi::UnverifiedDevices { room_id: rid, .. } => assert_eq!(rid, &room_id),
            other => panic!("expected UnverifiedDevices, got {other:?}"),
        }

        alice
            .client()
            .handle_ui_command(UiToDaemon::SendAnyways {
                message_id: "block-anyways".into(),
                pan_user: alice.user.user_id.clone(),
                room_id: room_id.clone(),
            })
            .await;

        let resp = send_task.await.expect("send task panicked");
        assert_eq!(resp.status(), StatusCode::OK, "SendAnyways must let the send through");

        // handle_ui_command also emits a Response{"M_OK", "Send allowed"}
        // signal on the same channel — drain it so the next case's wait for
        // UnverifiedDevices doesn't pick up this leftover instead.
        drain_signals(&mut alice.ui_rx);
    }

    // --- CancelSending case (same room, different device is still unverified) ---
    {
        let alice_router = alice.router.clone();
        let alice_token = alice.user.access_token.clone();
        let send_room_id = room_id.clone();
        let send_task = tokio::spawn(async move {
            let req = axum::http::Request::builder()
                .method("PUT")
                .uri(format!("/_matrix/client/v3/rooms/{send_room_id}/send/m.room.message/txn-block-cancel"))
                .header("Authorization", format!("Bearer {alice_token}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({ "msgtype": "m.text", "body": "cancel this" }).to_string(),
                ))
                .unwrap();
            alice_router.oneshot(req).await.unwrap()
        });

        let signal = tokio::time::timeout(Duration::from_secs(15), alice.ui_rx.recv())
            .await
            .expect("UnverifiedDevices signal timed out")
            .expect("ui_rx channel closed unexpectedly");
        assert!(matches!(signal, DaemonToUi::UnverifiedDevices { .. }));

        alice
            .client()
            .handle_ui_command(UiToDaemon::CancelSending {
                message_id: "block-cancel".into(),
                pan_user: alice.user.user_id.clone(),
                room_id: room_id.clone(),
            })
            .await;

        let resp = send_task.await.expect("send task panicked");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "CancelSending must reject the send with 403");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["errcode"], "M_FORBIDDEN");
    }
}

/// Cross-signing secret gossip after self-verification. Device A bootstraps
/// a brand-new cross-signing identity for the account; device B (a second,
/// independent session for the *same* account) starts out with none. After
/// A and B SAS-verify each other, `check_sas_states` should automatically
/// call `request_missing_secrets()` on B's side (since this is a
/// self-verification), and B should end up with a complete cross-signing
/// identity purely from the m.secret.request/m.secret.send round trip — no
/// recover-identity/SSSS step involved.
#[tokio::test]
#[ignore = "requires a real homeserver: ./scripts/testing/homeserver.sh up"]
async fn test_real_cross_signing_secret_gossip_after_self_verification() {
    require_real_homeserver().await;
    let base = homeserver_base_url();

    let user = register_user(&base, "selfverify").await;

    let mut device_a = build_party(&base, false, user.clone()).await;
    let mut device_b = build_party(&base, false, user.clone()).await;

    let (mut a_since, _) = device_a.sync_and_settle(None).await;
    let (mut b_since, _) = device_b.sync_and_settle(None).await;

    // Device A bootstraps a brand-new cross-signing identity for the account.
    device_a
        .client()
        .handle_ui_command(UiToDaemon::BootstrapCrossSigning {
            message_id: "bootstrap".into(),
            pan_user: device_a.user.user_id.clone(),
            reset: false,
        })
        .await;
    let a_status = device_a.client().cross_signing_status().await;
    assert!(a_status.is_complete(), "device A must have a complete cross-signing identity after bootstrap");
    let b_status = device_b.client().cross_signing_status().await;
    assert!(!b_status.is_complete(), "device B must start out without cross-signing secrets");

    let a_uid = device_a.user.user_id.clone();
    let a_did = device_a.user.device_id.clone();
    let b_uid = device_b.user.user_id.clone();
    let b_did = device_b.user.device_id.clone();

    // Let device B discover device A's freshly-uploaded device before
    // starting SAS — same reason as in test_real_sas_verification_round_trip.
    let (next, _) = device_a.sync_and_settle(a_since.as_deref()).await;
    a_since = next;
    let (next, _) = device_b.sync_and_settle(b_since.as_deref()).await;
    b_since = next;
    device_b.client().list_user_devices(&a_uid).await;

    device_a
        .client()
        .handle_ui_command(UiToDaemon::StartSas {
            message_id: "sas-start".into(),
            pan_user: a_uid.clone(),
            user_id: b_uid.clone(),
            device_id: b_did.clone(),
        })
        .await;

    let mut saw_invite = false;
    for _ in 0..MAX_ROUNDS {
        let (next, _) = device_b.sync_and_settle(b_since.as_deref()).await;
        b_since = next;
        if drain_signals(&mut device_b.ui_rx).iter().any(|e| {
            matches!(e, DaemonToUi::SasInvite { user_id, device_id, .. } if user_id == &a_uid && device_id == &a_did)
        }) {
            saw_invite = true;
            break;
        }
        tokio::time::sleep(ROUND_DELAY).await;
    }
    assert!(saw_invite, "device B must see device A's SasInvite");

    device_b
        .client()
        .handle_ui_command(UiToDaemon::AcceptSas {
            message_id: "sas-accept".into(),
            pan_user: b_uid.clone(),
            user_id: a_uid.clone(),
            device_id: a_did.clone(),
        })
        .await;

    let mut a_emoji = None;
    let mut b_emoji = None;
    for _ in 0..MAX_ROUNDS {
        let (next, _) = device_a.sync_and_settle(a_since.as_deref()).await;
        a_since = next;
        let (next, _) = device_b.sync_and_settle(b_since.as_deref()).await;
        b_since = next;

        for e in drain_signals(&mut device_a.ui_rx) {
            if let DaemonToUi::SasShow { emoji, .. } = e {
                a_emoji = Some(emoji);
            }
        }
        for e in drain_signals(&mut device_b.ui_rx) {
            if let DaemonToUi::SasShow { emoji, .. } = e {
                b_emoji = Some(emoji);
            }
        }
        if a_emoji.is_some() && b_emoji.is_some() {
            break;
        }
        tokio::time::sleep(ROUND_DELAY).await;
    }
    let a_emoji = a_emoji.expect("device A must see SasShow with emoji");
    let b_emoji = b_emoji.expect("device B must see SasShow with emoji");
    assert_eq!(a_emoji, b_emoji, "both sides must compute the same emoji sequence");

    device_a
        .client()
        .handle_ui_command(UiToDaemon::ConfirmSas {
            message_id: "sas-confirm-a".into(),
            pan_user: a_uid.clone(),
            user_id: b_uid.clone(),
            device_id: b_did.clone(),
        })
        .await;
    device_b
        .client()
        .handle_ui_command(UiToDaemon::ConfirmSas {
            message_id: "sas-confirm-b".into(),
            pan_user: b_uid.clone(),
            user_id: a_uid.clone(),
            device_id: a_did.clone(),
        })
        .await;

    // Keep syncing past SasDone: that's also when the auto-triggered
    // request_missing_secrets() fires on device B (is_self_verification()
    // is true for both sides here), and the actual gossip needs a couple
    // more round trips to land — device B's request out, device A's
    // auto-response out, device B importing it.
    let mut a_done = false;
    let mut b_done = false;
    let mut b_complete = false;
    for _ in 0..MAX_ROUNDS * 2 {
        let (next, _) = device_a.sync_and_settle(a_since.as_deref()).await;
        a_since = next;
        let (next, _) = device_b.sync_and_settle(b_since.as_deref()).await;
        b_since = next;

        if drain_signals(&mut device_a.ui_rx).iter().any(|e| matches!(e, DaemonToUi::SasDone { .. })) {
            a_done = true;
        }
        if drain_signals(&mut device_b.ui_rx).iter().any(|e| matches!(e, DaemonToUi::SasDone { .. })) {
            b_done = true;
        }

        if a_done && b_done && device_b.client().cross_signing_status().await.is_complete() {
            b_complete = true;
            break;
        }
        tokio::time::sleep(ROUND_DELAY).await;
    }
    let _ = a_since;
    let _ = b_since;

    assert!(a_done && b_done, "SAS verification must complete on both sides");
    assert!(
        b_complete,
        "device B must automatically receive device A's cross-signing secrets after self-verification"
    );
}
