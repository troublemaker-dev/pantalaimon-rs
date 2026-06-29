# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Pantalaimon is an E2E encryption-aware Matrix reverse proxy daemon written in Rust. It sits between Matrix clients and a homeserver, transparently encrypting outgoing messages and decrypting incoming ones. Crypto is handled by [Vodozemac](https://github.com/matrix-org/vodozemac) via `matrix-sdk-crypto`. No libolm or Python dependency.

## Commands

```bash
# Build (with D-Bus/panctl support)
cargo build --features ui

# Build without D-Bus (no panctl, works on macOS natively)
cargo build

# Run pantalaimon
cargo run --bin pantalaimon --features ui -- -c ~/.config/pantalaimon/pantalaimon.conf --data-path ~/.local/share/pantalaimon

# Run panctl (requires D-Bus, Linux only)
cargo run --bin panctl --features ui --

# Run tests
cargo test

# Run a specific test
cargo test test_name
```

## Container

D-Bus is Linux-only; the container is required on macOS to use panctl.

```bash
# Build image
podman build -t pantalaimon .

# Run
podman run -it --rm \
  --name pantalaimon \
  -v ~/.local/share/pantalaimon:/data \
  -v ~/.config/pantalaimon:/config \
  --publish 8009:8009 \
  -e RUST_LOG=pantalaimon=debug \
  pantalaimon \
  -c /config/pantalaimon.conf --data-path /data

# Use panctl inside the running container
podman exec -it pantalaimon panctl <command>
```

`entrypoint.sh` starts `dbus-daemon` at a fixed socket path before exec-ing `pantalaimon`. `DBUS_SESSION_BUS_ADDRESS` is baked into the image. The Dockerfile uses BuildKit cache mounts for the cargo registry and `target/` directory; subsequent builds only recompile changed crates.

## Crate layout

```
crates/
  pantalaimon/   — daemon binary + library
    src/
      main.rs       — startup, channel wiring, message_router task
      config.rs     — INI config parser (PanConfig, ServerConfig)
      client.rs     — PanClient: crypto, sync processing, SAS verification
      proxy/
        daemon.rs   — ProxyDaemon: per-server state, client registry
        routes.rs   — axum route handlers
        mod.rs
      dbus/
        server.rs   — DbusServer: zbus ControlIface + DevicesIface
        mod.rs
      messages.rs   — DaemonToUi / UiToDaemon enums
      store.rs      — PanStore: SQLite via sqlx (tokens, media keys)
      error.rs      — AppError
      lib.rs
  panctl/        — panctl binary (clap CLI + zbus client)
```

## Architecture

### Request flow

```
Matrix client → axum (ProxyDaemon, proxy/routes.rs)
                    ↓ intercepts select routes
                PanClient (client.rs, matrix-sdk-crypto OlmMachine)
                    ↓ no independent sync loop — driven by client syncs
                Matrix homeserver
```

`ProxyDaemon` handles all HTTP. It maintains one `PanClient` per logged-in user in `pan_clients`, looked up by access token via `token_to_user`. Intercepted routes:

- `POST /login` — creates `PanClient`, stores token
- `GET /sync` — initial sync is proxy-passed; subsequent syncs call `process_sync` then `run_post_sync_tasks` in a spawned task
- `GET /rooms/{id}/messages` — decrypts paginated history
- `PUT /rooms/{id}/send/{type}/{txn}` — encrypts outgoing events; blocks if unverified devices (unless `IgnoreVerification = True`)
- `POST /media/upload` — encrypts attachment, stores keys
- `GET /media/download/{server}/{id}` — fetches and decrypts attachment

### PanClient

`OlmMachine` is Arc-backed and internally synchronised; no external Mutex needed. `PanClient` itself is wrapped in `Arc<PanClient>` in the daemon.

**Sync processing** (`process_sync`):
1. Extract to-device events, device lists, OTK counts from sync body
2. `olm.receive_sync_changes()` — feeds crypto state machine
3. Track rooms gaining `m.room.encryption` state events
4. Decrypt `m.room.encrypted` timeline events in-place
5. `check_incoming_verifications()` — scan to-device events for `m.key.verification.request`, emit `SasInvite`

**Post-sync tasks** (`run_post_sync_tasks`, spawned so sync response returns immediately):
- `process_outgoing_requests()` — flush OlmMachine outgoing requests (keys/upload, keys/query, keys/claim, to-device, signature upload, room message)
- `check_pending_requests()` — for outgoing SAS flows, call `start_sas()` once remote accepts
- `check_sas_states()` — emit `SasShow` (emoji ready) and `SasDone` (done/cancelled); cleans up `active_sas`, `notified_show`, `notified_done`, `notified_invite` on flow end

**Unverified device check** uses `device.is_verified()` which covers both manual `LocalTrust::Verified` and cross-signing trust. Skips `self.user_id`. Blocked sends wait up to 30 seconds for a `SendAnyways` or `CancelSending` command from panctl.

### D-Bus / panctl

Two zbus interfaces at `/org/pantalaimon1`:
- `org.pantalaimon1.control` — verification flows, key import/export, identity recovery, send decisions
- `org.pantalaimon1.devices` — list/verify/blacklist devices

panctl is a one-shot subcommand CLI (not an interactive REPL). Each invocation connects to D-Bus, sends a command, waits for the response signal, and exits.

Signal flow: `DaemonToUi` messages are sent over an `mpsc` channel to `DbusServer`, which emits zbus signals. `UiToDaemon` commands arrive as D-Bus method calls and are routed by `message_router` in `main.rs` to the correct `PanClient`.

### Config

INI format, `[Default]` section + one section per server. Key options:

| Key | Default | Notes |
|-----|---------|-------|
| `LogLevel` | `Warning` | Error/Warning/Info/Debug |
| `Homeserver` | required | Upstream homeserver URL |
| `ListenAddress` | `localhost` | Use `0.0.0.0` in containers |
| `ListenPort` | `8009` | |
| `UseSSL` / `SSL` | `True` | Whether upstream uses HTTPS |
| `UseKeyring` | `True` | Set `False` in containers |
| `IgnoreVerification` | `False` | Skip unverified-device check |
| `DropOldKeys` | `False` | Prune duplicate Megolm sessions on startup |

### Store

`PanStore` uses sqlx + SQLite. Tables:
- `pan_server_user` — which users belong to which server
- `pan_access_token` — tokens when `UseKeyring = False`
- `pan_media_info` — media encryption keys keyed by `(server, mxc_server, mxc_path)`
- `pan_upload_info` — filename + mimetype for uploaded media
- `schema_version` — migration tracking

Crypto state (Olm/Megolm sessions, device keys, verification state) is stored separately per user in `matrix-sdk-sqlite` (`SqliteCryptoStore`) under `<data_dir>/crypto-<user>_<device>/`.

### Known limitations

- No independent sync loop — pantalaimon's OlmMachine is only updated when a client syncs through it. Verification requests from other clients won't be visible until the proxied client syncs.
- panctl is not interactive (no REPL); each command is a separate invocation.
- Blocked-send notifications require panctl to be running and watching; there are no OS notifications.
