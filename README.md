pantalaimon
===========

Pantalaimon is an end-to-end encryption aware Matrix reverse proxy daemon. It sits between a Matrix client and a homeserver, transparently encrypting outgoing messages and decrypting incoming ones. Clients connect to pantalaimon as if it were the homeserver; all crypto is handled internally using [Vodozemac](https://github.com/matrix-org/vodozemac) via matrix-sdk-crypto.

![Pantalaimon in action](docs/pan.gif)

## Running

### Container (recommended, required on macOS)

pantalaimon depends on D-Bus for the `panctl` control interface, which is Linux-only. The container is the recommended approach on macOS and any system where you don't want to install D-Bus natively.

```bash
podman build -t pantalaimon .
```

```bash
podman run -it --rm \
  --name pantalaimon \
  -v ~/.local/share/pantalaimon:/data \
  -v ~/.config/pantalaimon:/config \
  --publish 8009:8009 \
  -e RUST_LOG=pantalaimon=info \
  pantalaimon \
  -c /config/pantalaimon.conf --data-path /data
```

Use `panctl` inside the running container:

```bash
podman exec -it pantalaimon panctl <command>
```

### Local (Linux)

```bash
cargo build --release --features ui --bin pantalaimon --bin panctl
```

```bash
RUST_LOG=pantalaimon=info ./target/release/pantalaimon -c ~/.config/pantalaimon/pantalaimon.conf
```

```bash
./target/release/panctl <command>
```

### Local without D-Bus (any platform, no panctl)

```bash
cargo build --release --bin pantalaimon
RUST_LOG=pantalaimon=info ./target/release/pantalaimon -c ~/.config/pantalaimon/pantalaimon.conf
```

Device management commands are unavailable without `panctl`. Use `IgnoreVerification = True` in the config if you don't need device verification.

## Configuration

The config file uses INI format with a `[Default]` section and one section per homeserver proxy.

```ini
[Default]
LogLevel = Info

[my-server]
Homeserver = https://matrix.example.com
ListenAddress = localhost
ListenPort = 8009
UseKeyring = True
```

Place it at `~/.config/pantalaimon/pantalaimon.conf` or pass `-c /path/to/pantalaimon.conf`.

### Config reference

| Key | Default | Description |
|-----|---------|-------------|
| `LogLevel` | `Warning` | `Error`, `Warning`, `Info`, or `Debug` |
| `Homeserver` | *(required)* | URL of the upstream Matrix homeserver |
| `ListenAddress` | `localhost` | Address pantalaimon listens on |
| `ListenPort` | `8009` | Port pantalaimon listens on |
| `UseSSL` | `True` | Whether the upstream homeserver uses HTTPS |
| `UseKeyring` | `True` | Store access tokens in the OS keyring; set `False` in containers |
| `IgnoreVerification` | `False` | Skip the unverified-device check on send; useful for bots |
| `DropOldKeys` | `False` | Prune old inbound Megolm sessions on startup |

### Container config

Use `0.0.0.0` for `ListenAddress` so the port is reachable from outside the container, and `False` for `UseKeyring` since there is no OS keyring inside the container (tokens are stored in the data volume's SQLite DB instead).

```ini
[Default]
LogLevel = Info

[my-server]
Homeserver = https://matrix.example.com
ListenAddress = 0.0.0.0
ListenPort = 8009
UseKeyring = False
```

If the homeserver is running on the host machine, use `host.containers.internal` (Podman) or `host-gateway` (Docker) instead of `localhost`:

```ini
Homeserver = http://host.containers.internal:8448/
UseSSL = False
```

### Data directory

Crypto stores and the token database are written to `$XDG_DATA_HOME/pantalaimon` by default (`~/.local/share/pantalaimon` on most Linux systems). Override with `--data-path /path/to/dir`. In the container, mount this directory as a volume so state persists across restarts.

## Usage

1. Start pantalaimon.
2. Point your Matrix client at pantalaimon's `ListenAddress:ListenPort` instead of your homeserver.
3. Log in with your normal Matrix credentials — pantalaimon captures the session and handles all encryption from that point on.

Multiple clients can connect using the same access token once one has logged in. Multiple users per homeserver are supported.

## Device verification with panctl

Before pantalaimon will encrypt messages to a room, all other participants' devices must be verified (or `IgnoreVerification = True` must be set). Use `panctl` to manage this.

### List known devices for a user

```
panctl list-devices @alice:example.com @bob:example.com
```

Trust state is one of: `verified`, `cross-signing-verified`, `unset`, `blacklisted`, `ignored`.

### SAS emoji verification (recommended)

Initiate from panctl and confirm in the other client:

```
panctl start-verification @alice:example.com @bob:example.com BOB_DEVICE_ID
```

The other client will receive a verification request. Once accepted, both sides display matching emoji. Confirm in the other client first, then:

```
panctl confirm-verification @alice:example.com @bob:example.com BOB_DEVICE_ID
```

### Manual trust

If cross-signing verification already happened in another client (e.g. between iamb and ement), pantalaimon recognises that trust automatically. If you want to bypass SAS entirely:

```
panctl verify-device @alice:example.com @bob:example.com BOB_DEVICE_ID
```

### Handling a send blocked by unverified devices

When pantalaimon blocks a send, it waits up to 30 seconds for a decision from panctl:

```
panctl send-anyways @alice:example.com ROOM_ID    # send despite unverified devices
panctl cancel-sending @alice:example.com ROOM_ID  # cancel the send
```

### Restore cross-signing identity

If your account has SSSS set up (Security Key in your client's settings):

```
panctl recover-identity @alice:example.com
```

Enter your security key or passphrase when prompted. This imports the cross-signing keys and uploads device signatures immediately.

### Key import / export

```
panctl export-keys @alice:example.com /path/to/keys.txt passphrase
panctl import-keys @alice:example.com /path/to/keys.txt passphrase
```

## Running as a systemd service

### Native binary (Linux)

```bash
cp contrib/pantalaimon.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now pantalaimon
```

The service file uses `%h` to expand to your home directory. The binary is expected at `/usr/local/bin/pantalaimon`; adjust `ExecStart` if you installed elsewhere.

### Container via Podman Quadlet (Podman 4.4+)

Quadlet generates a systemd service from a `.container` file — no `podman run` command needed.

```bash
cp contrib/pantalaimon.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start pantalaimon
```

Edit the file to set the correct image name (matching what you passed to `podman build -t`) and any additional `PublishPort` entries for your config.

Use panctl via exec:

```bash
podman exec -it pantalaimon panctl <command>
```

## panctl command reference

| Command | Description |
|---------|-------------|
| `list-servers` | List configured homeserver proxies |
| `list-users` | List logged-in sessions |
| `list-devices <pan_user> <user_id>` | List known devices for a user |
| `verify-device <pan_user> <user_id> <device_id>` | Manually mark a device as verified |
| `unverify-device <pan_user> <user_id> <device_id>` | Remove manual verification |
| `blacklist-device <pan_user> <user_id> <device_id>` | Never encrypt to this device |
| `unblacklist-device <pan_user> <user_id> <device_id>` | Remove blacklist entry |
| `start-verification <pan_user> <user_id> <device_id>` | Start SAS emoji verification |
| `accept-verification <pan_user> <user_id> <device_id>` | Accept an incoming verification request |
| `confirm-verification <pan_user> <user_id> <device_id>` | Confirm emoji match |
| `cancel-verification <pan_user> <user_id> <device_id>` | Cancel verification in progress |
| `send-anyways <pan_user> <room_id>` | Allow a blocked send |
| `cancel-sending <pan_user> <room_id>` | Cancel a blocked send |
| `recover-identity <pan_user>` | Restore cross-signing from SSSS |
| `import-keys <pan_user> <file> <passphrase>` | Import E2E key backup |
| `export-keys <pan_user> <file> <passphrase>` | Export E2E keys |

`<pan_user>` is the full Matrix user ID of the session pantalaimon is managing (e.g. `@alice:example.com`).
