# BubbleUI

A focused, security-conscious admin UI for travel routers running vanilla
OpenWRT.

> Pre-alpha and built for personal use. Design pinned in
> [`DESIGN.md`](./DESIGN.md); not packaging-ready yet.

## What it is

BubbleUI is the four things you actually need on the road — hotel WiFi,
WireGuard with a real kill switch, a per-trip SSID with client isolation,
and encrypted DNS — wired together with sensible defaults and an
intentionally narrow surface. Auth is hardware-only: a YubiKey on the
router's USB port (HMAC-SHA1 challenge-response) or a registered
WebAuthn credential from the user's browser. No passwords anywhere.

Reference hardware is the **GL.iNet GL-AXT1800 (Slate AX)** running
**vanilla OpenWRT 23.05+** — GL.iNet's stock firmware is explicitly out
of scope. See [`DESIGN.md` §13](./DESIGN.md#13-hardware-target).

## Status

Source-of-truth: per the milestones in
[`DESIGN.md` §12](./DESIGN.md#12-milestones). High-level:

| Milestone | State |
|---|---|
| M0 — Design freeze                       | done — DESIGN.md §1–§13 |
| M1 — Frontend skeleton                   | done — Svelte 5 + Vite SPA |
| M2 — Auth daemon (YubiKey + WebAuthn + recovery) | done — `bubble-authd` over HTTP |
| M3 — Daemons + SPA wired end-to-end       | in progress — see below |
| M4 — VPN + DNS on real hardware           | not started |
| M5 — Packaging (`.ipk`)                   | not started |
| M6+ — Provider plugins (Proton/WARP/…)    | post-1.0 roadmap |
| M7 — Privacy hardening (MAC rotation, OUI, hostname) | post-1.0 roadmap |

What's wired today (testable on a Linux dev box, no router needed):

- `bubble-authd` — passwordless auth (YubiKey-on-router HMAC + WebAuthn
  from browser), recovery codes, sessions, `/api/time/sync`, `/auth/health`.
- `bubble-vpnd` — pool of WireGuard configs with parallel TCP-connect
  probing and "connect to fastest" selection. `wg-quick` integration is
  hardware-bound (currently a stub `Connector`).
- `bubble-netd` — captive-portal detection plus the §6.5 sign-in
  window state machine. nftables/dnsmasq integration is hardware-bound
  (`NoopApplier` records what it would do).
- `bubble-hwd` — LED state machine + GPIO buttons + a cross-daemon
  composer that polls the other three to drive the §13.5 LED states.
  `/sys/class/leds` and `/dev/input/event*` are hardware-bound.
- Frontend SPA — first-boot wizard, login, real `/vpn`, `/wifi`, and
  Dashboard panes. Each wired against the corresponding daemon.

## Install (on a router)

The shipping path is one OpenWRT `.ipk` per architecture, installed
on top of vanilla OpenWRT 23.05+. See [`DESIGN.md` §10](./DESIGN.md#10-build--install)
for the full rationale; the short version is:

```sh
# On the router:
opkg update
opkg install /tmp/bubbleui_<arch>.ipk
```

The package pulls `nginx-ssl`, `nftables`, `wireguard-tools`,
`dnsmasq-full`, `https-dns-proxy`, `yubikey-personalization`,
`px5g-mbedtls`, and `ca-bundle`. First-boot wiring (self-signed UI
cert, LAN firewall rule for 80/443, procd-supervised daemons) runs
automatically via `/etc/uci-defaults/bubbleui`.

Browse to `https://<router-ip>/`, accept the self-signed cert
exception, and run through the [§6.7 wizard](./DESIGN.md#67-first-boot-wizard).

`.ipk` artifacts are produced by the
[`package`](./.github/workflows/package.yml) workflow — currently
on tag pushes and on-demand. Pre-built downloads will live on the
GitHub Releases page once we tag a v0.1.

## Quick start (dev)

```sh
# One-shot launcher: builds all four daemons, provisions a mock
# YubiKey, starts everyone, and execs into pnpm dev. Ctrl-C tears
# down the lot.
./scripts/dev.sh

# The SPA loads at http://localhost:5173 and Vite proxies /auth, /api,
# /vpn, /net, /hw to their respective daemons on 127.0.0.1.
```

If you'd rather run pieces individually:

```sh
cd backend
go test ./...                                      # 19 packages
go run ./cmd/bubble-authd -mock provision          # one-off CLI
go run ./cmd/bubble-authd -mock serve -insecure -rp-id localhost
go run ./cmd/bubble-vpnd
go run ./cmd/bubble-netd
go run ./cmd/bubble-hwd -mock

cd ../frontend
pnpm install && pnpm fonts                         # downloads Nerd Font
pnpm dev
```

## Layout

```
.
├── DESIGN.md                — single source of truth
├── README.md                — this
├── frontend/                — Svelte 5 + Vite SPA (see frontend/README.md)
├── backend/                 — Go module: four daemons + tests (see backend/README.md)
├── package/bubbleui/        — OpenWRT .ipk skeleton (Makefile, init.d, UCI, nginx)
├── scripts/dev.sh           — multi-daemon dev launcher
├── .github/workflows/
│   ├── ci.yml               — push CI: tests, vet, gofmt, svelte-check, build
│   └── package.yml          — tagged-release CI: build .ipk per arch
└── .claude/                 — SessionStart hook for cloud dev sessions
```

`backend/cmd/` houses the four daemons (`bubble-authd`, `bubble-vpnd`,
`bubble-netd`, `bubble-hwd`); `backend/internal/` is the supporting
packages.

## Scope notes

- This is a personal project. The author is the user. Suggestions and
  PRs are welcome but the design is intentionally opinionated and
  decisions live in [`DESIGN.md`](./DESIGN.md).
- No telemetry, ever (DESIGN.md §11.4). Crash reports go to GitHub
  Issues as a redacted log bundle the user reviews and submits manually.
- Stock GL.iNet firmware is not supported; the only target is vanilla
  OpenWRT.

## License

MIT — see [`LICENSE`](./LICENSE).
