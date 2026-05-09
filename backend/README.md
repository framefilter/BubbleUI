# BubbleUI — backend

Go services that back the BubbleUI web UI. M2 ships `bubble-authd` as a
CLI exercising the auth flows from `DESIGN.md` §5 (provision a YubiKey
HMAC credential, log in, recover). HTTP and `ubus` surfaces land in M3.

## Quick start

```sh
cd backend
go test ./...

# End-to-end CLI demo, no hardware required:
go run ./cmd/bubble-authd -db /tmp/creds.db -mock provision
go run ./cmd/bubble-authd -db /tmp/creds.db -mock login
go run ./cmd/bubble-authd -db /tmp/creds.db -mock status
```

`-mock` swaps in an in-memory YubiKey emulator and persists the
generated slot-2 secret to a sidecar file next to the DB so subsequent
invocations can re-create the same virtual key.

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
│   └── bubble-authd/      M2 CLI; M3 grows it into the daemon
├── internal/
│   ├── auth/              ProvisionYubiKey / LoginYubiKey / Recover
│   ├── crypto/            self-wrap (HMAC→HKDF→AES-256-GCM), recovery codes
│   ├── store/             SQLite credentials.db (modernc.org/sqlite, no CGO)
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

## What's not yet wired

- HTTP / ubus surface (M3).
- WebAuthn registration and assertion verification (M3 — schema is in
  place, the `auth` flows are stubbed pending the HTTP layer).
- LED state callouts via `bubble-hwd` (M3 once that exists).
- Cross-compilation to OpenWRT's `ipq60xx` target (M3+).
