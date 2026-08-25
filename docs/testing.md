# Testing

There are two layers of tests in this repo.

## 1. Mocked tests (default `cargo test`)

```bash
cargo test
```

This runs the unit tests embedded in `client.rs`/`config.rs`/etc. and the
`wiremock`-based integration tests in `crates/pantalaimon/tests/proxy_test.rs`.
`proxy_test.rs` stands up a fake homeserver with `wiremock` and drives a
single `PanClient`/`OlmMachine` through the axum router. That's enough to
cover proxy routing logic (which routes get intercepted, header handling,
media encryption, etc.), but it can't exercise real key exchange: there's
only ever one crypto identity in the test, so Olm session establishment,
Megolm room-key sharing, and SAS device verification never actually happen
between two independent parties.

No container, network access, or setup is required for this layer. It's
fully hermetic and safe to run anywhere, including CI.

## 2. Real key-exchange tests (`crates/pantalaimon/tests/key_exchange_test.rs`)

These stand up **two independent `PanClient`/`OlmMachine` identities**
(alice and bob) against a **real** Matrix homeserver
([continuwuity](https://continuwuity.org/)) running in a container, and
drive real HTTP traffic between them — real `keys/upload`, `keys/query`,
`keys/claim`, and to-device delivery — so the actual crypto handshake is
exercised end to end, not mocked.

Three scenarios are covered:

| Test | What it proves |
|---|---|
| `test_real_key_exchange_encrypt_decrypt_roundtrip` | Alice sends a real Megolm-encrypted message; bob's independent OlmMachine actually decrypts it after a real to-device room-key relay. |
| `test_real_sas_verification_round_trip` | Full emoji SAS verification round trip (`StartSas` → `AcceptSas` → matching emoji → `ConfirmSas` → `SasDone` on both sides), driven via `PanClient::handle_ui_command` — the same function `message_router`/D-Bus calls in production, just without the D-Bus transport. |
| `test_real_unverified_device_send_block_flow` | A send into a room with an unverified device blocks, emits `UnverifiedDevices`, and only proceeds/cancels once `SendAnyways`/`CancelSending` arrives — the code path fixed by "Fix silent failures in the unverified-device send-block flow". |

They are `#[ignore]`d, so plain `cargo test` never touches the network.
Run them explicitly:

```bash
./scripts/testing/homeserver.sh up
cargo test --test key_exchange_test -- --ignored --test-threads=1 <test-name>
./scripts/testing/homeserver.sh down
```

**Run one test at a time** (pass its name as shown above). See
[Known limitations](#known-limitations) below for why.

These tests are **not wired into CI** yet — they're a local/manual dev tool
for now. CI wiring can follow once the harness has proven stable across
runtimes.

### Prerequisites

You need a container runtime, plus `curl` and `jq` on your `PATH`.

#### Apple `container` (macOS)

```bash
brew install --cask container   # if not already installed
container system start          # required once per boot — see below
```

`scripts/testing/homeserver.sh` auto-detects `container` first if no
explicit runtime is configured. Two gotchas specific to this tool, found
while building this harness:

- **`container system start` must be run before anything else.** Without
  it, every `container` subcommand fails with an XPC connection error
  (`failed to list containers ... Connection invalid`). The script does
  *not* do this for you automatically on every invocation — run it once
  per reboot (or after `container system stop`).
- **Named volumes aren't created implicitly.** Unlike Docker/Podman, `container run -v <name>:/path` does not auto-create a missing volume; the
  script explicitly runs `container volume create` first.

#### Docker

```bash
# Standard Docker Desktop / docker CLI install — no special notes.
```

#### Podman (macOS)

```bash
brew install podman
podman machine init
podman machine start   # required once — podman has no VM running by default on macOS
```

#### Overriding runtime selection

```bash
CONTAINER_RUNTIME=docker ./scripts/testing/homeserver.sh up
```

Detection order when unset: `container` → `docker` → `podman` (same
precedence `../relay/scripts/seed-homeserver.sh` uses, which this script's
container-provisioning logic is ported from).

### `scripts/testing/homeserver.sh`

```bash
./scripts/testing/homeserver.sh up             # start (or reuse) the homeserver, idempotent
./scripts/testing/homeserver.sh status          # check reachability + container state
./scripts/testing/homeserver.sh down            # stop + remove the container
./scripts/testing/homeserver.sh down --wipe     # also delete the data volume
```

Unlike relay's `seed-homeserver.sh`, this script is fully **non-interactive**
(no `read` prompts) so it's safe to script/automate. `up` is idempotent: if
the container's already running, it just confirms reachability and exits.

On a completely fresh volume, continuwuity requires a one-time **bootstrap
registration token** printed to its own container logs (the static
`CONTINUWUITY_REGISTRATION_TOKEN` env var only becomes valid once at least
one account exists). `up` handles this automatically — it tries the static
token first, and only falls back to scraping the bootstrap token from
container logs if that fails.

The homeserver listens on `http://localhost:8008`. Override with
`PANTALAIMON_TEST_HOMESERVER=http://localhost:8123` if you're running it
elsewhere (e.g. you started it yourself, outside this script).

### Known limitations

- **Run real-homeserver tests one at a time.** While building this harness,
  running multiple `#[ignore]`d tests together in one `cargo test`
  invocation (e.g. the plain `cargo test --test key_exchange_test --
  --ignored`, no name filter) was repeatedly observed to hang indefinitely
  on the *second* test's HTTP calls — specifically against Apple's
  `container` runtime, and specifically only when more than one test ran in
  the same process. Every individual test passes reliably and quickly
  (under ~1.5s) on its own, including immediately after a full
  `container system stop && container system start`. The cause wasn't
  pinned down after ruling out connection-pool reuse, stale volume state,
  and registered-user count — it did not reproduce when each test was
  invoked as its own separate `cargo test` process. If you hit a hang,
  kill it and retry with a single test-name filter; if it's still flaky,
  restart the container system (`container system stop && container
  system start`) or fully recreate the homeserver (`./scripts/testing/homeserver.sh down --wipe && ./scripts/testing/homeserver.sh up`).
  This hasn't been characterized on Docker/Podman — if you need to run the
  full suite unattended (e.g. in CI down the line), try one of those first.
- Tests register fresh, uniquely-named users (`<prefix>-<pid>-<timestamp>-<n>`)
  on every run, so it's safe to run them repeatedly against the same
  persistent volume without wiping — no manual cleanup needed between runs.

### Env vars

| Var | Default | Purpose |
|---|---|---|
| `PANTALAIMON_TEST_HOMESERVER` | `http://localhost:8008` | Base URL of the real homeserver the tests target. |
| `CONTAINER_RUNTIME` | auto-detected | Overrides `scripts/testing/homeserver.sh`'s runtime selection (`container`/`docker`/`podman`). |
