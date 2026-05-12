# BubbleUI — backend

Go services that back the BubbleUI web UI.

- `bubble-authd` — auth flows from DESIGN.md §5 (WebAuthn registration
  and login, recovery code), exposed over HTTP for the SPA.
- `bubble-vpnd` — DESIGN.md §6.2 / §11.5 VPN strategy: a pool of
  saved WireGuard configs, parallel TCP-connect probing, "connect to
  fastest" as the default action. wg-quick integration lives behind
  a Connector interface; the dev binary uses StubConnector.
- `bubble-netd` — DESIGN.md §6.5 captive-portal detection + the
  time-boxed sign-in window state machine. nftables / dnsmasq
  integration lives behind an Applier interface; the dev binary
  uses NoopApplier and logs what it would have done.
- `bubble-hwd` — DESIGN.md §13.5/§13.6 hardware adapter: status LED
  state machine + GPIO button events. Drives /sys/class/leds on the
  router (auto-detects mono vs RGB) and /dev/input/event* for
  buttons. Dev binary uses MockDriver; pass -mock to force.

`ubus` integration on the router lands in M3 proper. For now all
four daemons run as independent HTTP servers (8765 / 8766 / 8767 / 8768).

## Quick start

```sh
cd backend
go test ./...

# Run the daemon — WebAuthn registration/login happens from a browser:
go run ./cmd/bubble-authd -db /tmp/creds.db serve -insecure -rp-id bubble.local
# now: curl http://127.0.0.1:8765/auth/session/whoami
```

WebAuthn requires `-rp-id` matching the hostname the SPA is loaded from
(no scheme/port). The four `/auth/webauthn/*` endpoints are disabled
without it; the rest of the server still works for `recover`, `whoami`,
`logout`, time-sync, and the setup-status probe.

## HTTP surface

All endpoints return JSON. Cookies are `bubble-session`,
`HttpOnly; SameSite=Strict; Secure` (Secure dropped only with
`-insecure`).

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/auth/webauthn/register/begin`    | `{}`                                 | Starts a registration ceremony. Returns `{handle, options}`; forward `options.publicKey` to `navigator.credentials.create()`. |
| POST | `/auth/webauthn/register/finish`   | `{handle, response, label?}`         | Validates the attestation, persists the credential. Auth-gated: requires a session unless no credentials are registered yet. |
| POST | `/auth/webauthn/login/begin`       | `{}`                                 | Starts an authentication ceremony. Returns `{handle, options}`; forward to `navigator.credentials.get()`. |
| POST | `/auth/webauthn/login/finish`      | `{handle, response}`                 | Validates the assertion, mints a session cookie. |
| POST | `/auth/recover`                    | `{"code":"…"}`                       | Runs §5.4 recovery. Wipes credentials and revokes all sessions. |
| GET  | `/auth/session/whoami`             | n/a                                  | Returns `{authenticated, credential_id, expires_at}`. |
| POST | `/auth/session/logout`             | none                                 | Revokes the current session. |
| POST | `/api/time/sync`                   | `{"now":<ms>, "force":bool}`         | Browser-supplied time per §6.6. Without `force`, reports skew but never sets the clock. |

### `serve` flags

| flag | default | purpose |
|---|---|---|
| `-listen ADDR`           | `127.0.0.1:8765` | listen address |
| `-tls-cert FILE -tls-key FILE` | unset | enable TLS; otherwise plain HTTP behind uhttpd |
| `-insecure`              | false  | drop the `Secure` cookie flag (plain-HTTP dev) |
| `-allowed-origin URL,…`  | unset  | comma-separated Origin allowlist; empty = no check |
| `-allow-set-time`        | false  | wire `/api/time/sync` to actually call `date -s` when `force=true`. Without this, the endpoint can only *report* skew. |
| `-rp-id HOST`            | unset  | WebAuthn Relying Party ID (the host without scheme/port — e.g. `bubble.local`). Empty disables the four `/auth/webauthn/*` endpoints. |
| `-rp-name NAME`          | `BubbleUI` | WebAuthn display name shown in the browser's authenticator UI. |

## Running against a real security key

WebAuthn ceremonies run in the browser, not the daemon — point the SPA
at the running `bubble-authd` (`-rp-id` matching the SPA's hostname) and
register/log in from there. Any FIDO2 authenticator works: YubiKey 5+,
SoloKey, Touch ID, Windows Hello, Android platform authenticator.

The router-attached YubiKey HMAC-SHA1 challenge-response path that
earlier builds shipped has been removed (upstream OpenWRT dropped
`yubikey-personalization` from its package feed; see DESIGN.md §5
and §11 for the future FIDO2 hmac-secret successor that will restore
HW-bound at-rest wrap).

## Layout

```
backend/
├── cmd/
│   ├── bubble-authd/      auth daemon (CLI + HTTP)
│   ├── bubble-vpnd/       VPN daemon (HTTP, /vpn surface)
│   ├── bubble-netd/       net/firewall daemon (HTTP, /net surface)
│   └── bubble-hwd/        hardware adapter daemon (HTTP, /hw surface)
├── internal/
│   ├── auth/              WebAuthn register/login/recover
│   ├── crypto/            recovery-code primitives
│   ├── store/             auth SQLite (credentials.db)
│   ├── session/           HTTP session minting / validation / revocation
│   ├── httpapi/           bubble-authd HTTP handlers
│   ├── webauthn/          go-webauthn wrapper + pending-flow state
│   ├── wgpool/            VPN config SQLite + .conf parser
│   ├── prober/            parallel TCP-connect probe
│   ├── selector/          rank candidates by probe RTT
│   ├── vpnapi/            bubble-vpnd HTTP handlers + StubConnector
│   ├── captive/           captive-portal detection probe
│   ├── signin/            §6.5 sign-in window state machine + Applier
│   ├── netapi/            bubble-netd HTTP handlers
│   ├── led/               LED state machine + Mock/Sysfs drivers
│   ├── buttons/           GPIO button events (Mock + Linux stub)
│   └── hwapi/             bubble-hwd HTTP handlers
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
  setter / bad input), security headers, Origin allowlist,
  WebAuthn register/login bootstrap-vs-auth-gated paths.
- `webauthn`: engine wraps go-webauthn — begin returns valid options,
  unknown handle rejected, malformed body rejected, handles consumed
  exactly once, expired handles purged via Sweep().

## What's not yet wired

- ubus surface (M3 proper). The HTTP server is a transitional shape —
  on the router it'll sit behind uhttpd's TLS termination, while
  `bubble-vpnd` / `bubble-netd` / `bubble-hwd` come up as ubus objects.
- LED state callouts via `bubble-hwd` (M3 once that exists).
- Cross-compilation to OpenWRT's `ipq60xx` target (M3+).
- The cryptographic happy path of WebAuthn finish/login — exercised
  only by real browsers. Wiring + error-path coverage is unit-tested.
