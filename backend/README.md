# BubbleUI — backend

Go services that back the BubbleUI web UI. `bubble-authd` runs the
auth flows from `DESIGN.md` §5 (provision, log in, recover) and now
exposes them over HTTP for the SPA. `ubus` integration lands in M3
proper, alongside the rest of the network/firewall daemons.

## Quick start

```sh
cd backend
go test ./...

# End-to-end CLI demo, no hardware required:
go run ./cmd/bubble-authd -db /tmp/creds.db -mock provision
go run ./cmd/bubble-authd -db /tmp/creds.db -mock login
go run ./cmd/bubble-authd -db /tmp/creds.db -mock status

# HTTP server (on top of the same DB):
go run ./cmd/bubble-authd -db /tmp/creds.db -mock serve -insecure
# now: curl http://127.0.0.1:8765/auth/session/whoami
#      curl -X POST http://127.0.0.1:8765/auth/yubikey/login
```

`-mock` swaps in an in-memory YubiKey emulator and persists the
generated slot-2 secret to a sidecar file next to the DB so the
`serve` subcommand can re-create the virtual key state on startup.

## HTTP surface

All endpoints return JSON. Cookies are `bubble-session`,
`HttpOnly; SameSite=Strict; Secure` (Secure dropped only with
`-insecure`).

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/auth/yubikey/login`     | none                 | Runs §5.3 YubiKey login. Mints a session cookie. |
| POST | `/auth/recover`           | `{"code":"…"}`       | Runs §5.4 recovery. Wipes credentials and revokes all sessions. |
| GET  | `/auth/session/whoami`    | n/a                  | Returns `{authenticated, credential_id, expires_at}`. |
| POST | `/auth/session/logout`    | none                 | Revokes the current session. |
| POST | `/api/time/sync`          | `{"now":<ms>, "force":bool}` | Browser-supplied time per §6.6. Without `force`, reports skew but never sets the clock. |

### `serve` flags

| flag | default | purpose |
|---|---|---|
| `-listen ADDR`           | `127.0.0.1:8765` | listen address |
| `-tls-cert FILE -tls-key FILE` | unset | enable TLS; otherwise plain HTTP behind uhttpd |
| `-insecure`              | false  | drop the `Secure` cookie flag (plain-HTTP dev) |
| `-allowed-origin URL,…`  | unset  | comma-separated Origin allowlist; empty = no check |
| `-allow-set-time`        | false  | wire `/api/time/sync` to actually call `date -s` when `force=true`. Without this, the endpoint can only *report* skew. |

## Running against a real YubiKey

```sh
# Linux deps:
#   Debian/Ubuntu:  apt install yubikey-personalization yubikey-manager
#   Arch:           pacman -S yubikey-personalization yubikey-manager

go run ./cmd/bubble-authd provision
# → prints recovery code + slot-2 secret in hex

# Program the physical key with the printed secret:
ykman otp chalresp --touch 2 <hex-secret>

# Now log in:
go run ./cmd/bubble-authd login
```

The daemon shells out to `ykchalresp` for the HMAC-SHA1 challenge.
Touch the key when it blinks.

## Layout

```
backend/
├── cmd/
│   └── bubble-authd/      CLI + HTTP server
├── internal/
│   ├── auth/              ProvisionYubiKey / LoginYubiKey / Recover
│   ├── crypto/            self-wrap (HMAC→HKDF→AES-256-GCM), recovery codes
│   ├── store/             SQLite credentials.db (modernc.org/sqlite, no CGO)
│   ├── session/           HTTP session minting / validation / revocation
│   ├── httpapi/           HTTP handlers + Origin/security middleware
│   └── yubikey/           ykchalresp adapter + Mock for tests
└── go.mod
```

## What's tested without hardware

All four packages have unit tests that run on plain `go test ./...`:

- `crypto`: self-wrap roundtrip, tamper rejection, wrong-key rejection,
  recovery-code generation/normalization/uniqueness.
- `store`: schema migration idempotency, credential CRUD, recovery-code
  set/get/burn.
- `yubikey`: `Mock` correctness (HMAC-SHA1 deterministic, unprogrammed
  slot rejection, plug/unplug state).
- `auth`: provision → login happy path, wrong-key rejection, no-key
  rejection, full recovery flow including single-use enforcement and
  normalization tolerance.
- `session`: token uniqueness, sliding expiration, expiry cleanup,
  revoke / revoke-all, purge of expired rows.
- `httpapi`: every endpoint exercised via `httptest.Server` —
  login happy path, login rejected without/with-wrong key, whoami
  in both states, logout, recover (good code + bad code + missing
  code), time-sync (in tolerance / out of tolerance / force / no
  setter / bad input), security headers, Origin allowlist.

## What's not yet wired

- ubus surface (M3 proper). The HTTP server is a transitional shape —
  on the router it'll sit behind uhttpd's TLS termination, while
  `bubble-vpnd` / `bubble-netd` / `bubble-hwd` come up as ubus objects.
- WebAuthn registration and assertion verification. The schema and
  credential model already accommodate it; flows land next.
- LED state callouts via `bubble-hwd` (M3 once that exists).
- Cross-compilation to OpenWRT's `ipq60xx` target (M3+).
