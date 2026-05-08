# BubbleUI — Design

A simple, security-conscious web UI for OpenWRT travel routers.

> Status: pre-alpha design. Nothing here is implemented yet.
> This document is the source of truth for the v0 scope and will move/evolve as code lands.

---

## 1. Goals

1. **One-screen-per-task.** Hotel WiFi, VPN, travel SSID, DNS — each is a single page with sensible defaults.
2. **Secure by default.** Kill-switch on, client isolation on, encrypted DNS on, admin UI gated by a hardware key.
3. **Small.** Runs on vanilla OpenWRT routers with as little as 128 MB RAM and 32 MB flash. Bundle target: < 150 KB gzipped JS+CSS.
4. **No proprietary daemons.** All state lives in UCI; all RPC goes through `ubus` via `rpcd` with narrow ACLs.
5. **Travel-shaped UX.** Captive portals, hotel WiFi, tethering, kill-switch, mobile-first layout.

## 2. Non-goals (v0)

- A full LuCI replacement. We expose a focused subset; LuCI stays installed for power users.
- Mesh, multi-AP, enterprise auth, IPv6 prefix delegation tuning, advanced QoS.
- GL.iNet stock firmware compatibility. Targeting **vanilla OpenWRT 23.05+** first; GL.iNet coexistence is a follow-up.
- A mobile app. The UI is a responsive PWA.

## 3. Threat model

**Assumed adversary**

- Hostile network on the WAN side (hotel/airport WiFi, untrusted ISP).
- Casual local-network attackers on the LAN side (other hotel guests on the same network you're tethered to).
- Opportunistic theft of the router itself.

**In scope**

- Plaintext DNS leakage on hostile networks.
- Traffic leakage when a configured VPN tunnel drops.
- Unauthorised admin access via the LAN port or stolen device.
- Replayed or reused web admin sessions.
- Captive portal tampering (we connect to a known-good URL to detect).

**Out of scope (v0)**

- Persistent firmware-level compromise.
- Coercion-resistant deniability.
- Side-channel attacks on the YubiKey itself.

**Mitigations (summary)**

| Threat | Mitigation |
|---|---|
| DNS leaks | Force DoH/DoT; firewall blocks port 53 to anything but the local resolver |
| VPN drop | `firewall` zone with `forward=REJECT`, route LAN egress only via `wg0` |
| Stolen device | All admin UI access requires a USB-attached YubiKey + password |
| Lost key abroad | Single-use printed recovery code, hash-stored on router |
| Replay/CSRF | `rpcd` session tokens, `SameSite=Strict`, double-submit token on mutations |
| Captive-portal MITM of admin UI | Admin UI is only reachable on LAN IP, never WAN; HSTS; self-signed cert pinned in setup wizard |

## 4. Architecture

```
+---------------------------+
|  Browser (Svelte SPA)     |
|  - PWA, offline-capable   |
|  - WebAuthn (optional 2FA)|
+-------------+-------------+
              | HTTPS (uhttpd, self-signed)
              v
+-------------+-------------+
|  uhttpd                   |
|   /  -> static SPA        |
|   /ubus -> rpcd JSON-RPC  |
|   /auth -> auth helper    |
+------+-------------+------+
       |             |
       v             v
+--------------+  +-----------------+
|  rpcd / ubus |  |  bubble-authd   |
|  (UCI, net,  |  |  (shell/Go)     |
|   wireless,  |  |  - ykchalresp   |
|   firewall)  |  |  - issues rpcd  |
|              |  |    sessions     |
+------+-------+  +--------+--------+
       |                   |
       v                   v
   UCI / netifd       USB (ykpers, libusb)
```

**Why this shape**

- Reusing `ubus`/`rpcd` means we inherit OpenWRT's existing auth model (sessions, ACL groups, audit logs) and don't ship a parallel privilege boundary.
- The auth helper is the *only* component that talks to USB. Everything else stays declarative UCI calls.
- A clean uhttpd → rpcd path lets us drop in mTLS or a future binary auth daemon without changing the SPA.

## 5. Authentication

### 5.1 Decisions

- **Scope:** *all* UI access requires a key-backed session. No anonymous status page.
- **Primary factor:** USB-attached YubiKey (or compatible: Nitrokey Pro/3, OnlyKey) on the **router**, via HMAC-SHA1 challenge-response (`ykchalresp`).
- **Optional 2FA:** WebAuthn from the **client** browser (any FIDO2 authenticator). The user can enable this on the security page; the server treats it as an additional required factor.
- **Recovery:** printed recovery code shown once at provisioning, BLAKE2s-hashed on disk, single-use to disable the key requirement.
- **Note on PAM:** `pam_yubico` does support exactly this challenge-response model, but `uhttpd` doesn't authenticate through PAM. We replicate the model in `bubble-authd` rather than bolt PAM into the web stack.

### 5.2 Provisioning flow (first boot)

1. Router boots into a one-time setup mode on `192.168.8.1`. Firewall blocks WAN until setup completes.
2. User plugs in a YubiKey. Setup wizard:
   - Generates a 20-byte random secret `S`.
   - Writes `S` to YubiKey slot 2 (HMAC-SHA1, variable input).
   - Stores `S` encrypted at rest under a key derived from the user's chosen admin password (Argon2id).
   - Generates a 128-bit recovery code, displays it once, stores `BLAKE2s(code)` on disk.
3. User sets admin password. Setup mode exits; future logins require key + password.

### 5.3 Login flow

1. User submits password over HTTPS.
2. `bubble-authd` derives the at-rest key from the password (Argon2id), unwraps `S`.
3. Daemon enumerates USB; if no compatible key present → reject.
4. Daemon generates random 64-byte challenge `C`, calls `ykchalresp -2 C` against the device.
5. Daemon recomputes `HMAC-SHA1(S, C)` locally and compares. Constant-time eq.
6. On match, daemon calls `ubus call session login` and returns the session token to the browser as `HttpOnly; Secure; SameSite=Strict`.
7. If WebAuthn 2FA is enabled, the SPA issues a `navigator.credentials.get()` challenge before any mutation; signed assertion is verified by `bubble-authd`.

### 5.4 Recovery flow

1. User clicks "Lost my key" on the login page.
2. Enters admin password + the printed recovery code.
3. Server checks `BLAKE2s(code)` against stored hash, in constant time.
4. If valid, the code is **burned** (replaced with random bytes), the key requirement is disabled, and the UI forces the user to re-provision before any other action.

### 5.5 What this does *not* protect against

- An attacker with physical access to both the router and the key. (Mitigation: admin password is still required.)
- A YubiKey with a known-weak slot 2 secret pre-provisioned by a hostile party. (Mitigation: always provision from setup mode on a fresh router.)

## 6. MVP features

### 6.1 Hotel WiFi + captive portal

- Scan visible SSIDs (`iwinfo`).
- Configure `wwan` interface as a station; bring up `wlan0` as STA + `wlan1` as AP simultaneously where the radio supports it.
- Captive-portal probe: HTTP GET to a hardcoded list of known endpoints (e.g. `http://detectportal.firefox.com/success.txt`). Mismatch → assume captive portal.
- UI offers "Open hotel login" which iframes/redirects the user to the captive portal page; we never inject credentials.

### 6.2 WireGuard client + kill switch

- Import config: paste `.conf`, scan QR, or upload file.
- One-tap connect; status pill shows handshake age.
- Kill switch: dedicated `wg` firewall zone with `forward=REJECT`, LAN zone forwards only to `wg`. When `wg0` is down, no LAN→WAN forwarding exists.
- DNS in the tunnel uses `Endpoint`-side DNS or our DoH resolver, never the hotel's.

### 6.3 Travel SSID with isolation

- Per-trip SSID name + WPA2/3-SAE password (default WPA3-SAE, fallback mixed).
- `isolate=1` on the AP by default.
- Optional guest VLAN with its own DHCP scope and zero LAN access.
- "Forget this trip" wipes the SSID, password, leases, and ARP cache.

### 6.4 Encrypted DNS (DoH/DoT)

- Default to `https-dns-proxy` listening on 127.0.0.1:5053, dnsmasq forwards to it.
- Default upstream: Quad9 (`9.9.9.9` / `dns.quad9.net`). User-pickable: Cloudflare, Mullvad, NextDNS, custom.
- Firewall rule blocks outbound TCP/UDP 53 from LAN to anything except the local resolver. Prevents apps that hardcode `8.8.8.8`.

## 7. Frontend

### 7.1 Stack

- **Svelte 5** + **Vite** + **TypeScript**.
- No router library; a 60-line hash-router suffices for ~6 screens.
- No UI library. Hand-rolled components, CSS variables for theming.
- State: Svelte stores. No Redux/Pinia/etc.
- API client: a single `rpc.ts` module wrapping `fetch` to `/ubus`.

### 7.2 Typography

We're using a **Nerd Font** as both UI and icon font. This avoids shipping an icon set (Lucide/Feather are ~30-50 KB even tree-shaken) — instead we render glyphs like `` (wifi) directly.

**Default: Monaspace Neon (Nerd Font Mono)** — `MonaspiceNe`.

- GitHub-maintained, actively developed.
- Texture-healing for clean rendering at small sizes.
- Five complementary variants (Neon, Argon, Xenon, Radon, Krypton) we can use for hierarchy without changing weight.
- Subsetted to Latin + Nerd Font private-use glyphs we actually reference, shipped as WOFF2. Target font payload < 60 KB.

**Alternates documented** for the user to swap via a CSS variable: Maple Mono NF, JetBrainsMono Nerd Font, CommitMono Nerd Font, CaskaydiaCove Nerd Font.

Body text uses the same monospace at 14 px / 1.55 line-height. Going monospace-only is a design choice — it reads as a serious sysadmin tool, not a consumer gadget, which matches the security-conscious posture.

### 7.3 Theming

- Dark default; light theme available.
- Two accent colors: signal-green for "secured" states, amber for "needs attention", red reserved for failures only.
- Respects `prefers-reduced-motion` and `prefers-color-scheme`.

## 8. Backend

### 8.1 Components

| Component | Language | Role |
|---|---|---|
| `bubble-authd` | shell + `ykchalresp` (v0); Go (v1) | YubiKey challenge, password verification, session minting |
| `bubble-rpcd-acl` | JSON | ACL files declaring exactly which `ubus` paths the UI may call |
| `bubble-uhttpd-conf` | uhttpd config | Serves SPA, terminates TLS, proxies `/ubus` and `/auth` |
| `bubble-setup` | shell | First-boot wizard helper, drives provisioning |

### 8.2 ACL surface (initial draft)

Reads:

- `network.interface.*` — status of `lan`, `wan`, `wwan`, `wg0`
- `iwinfo` — scan, assoclist
- `service.list` — what's running
- `system.info`, `system.board`

Writes (gated by valid session):

- `uci` for `network`, `wireless`, `firewall`, `dhcp`, `https-dns-proxy`
- `service` for `network`, `firewall`, `https-dns-proxy`, `wireguard`

Anything else is denied. ACL files are versioned in this repo.

## 9. Repository layout (planned)

```
/
├── DESIGN.md            (this file)
├── README.md
├── frontend/            Svelte + Vite app
│   ├── src/
│   ├── public/
│   └── package.json
├── backend/
│   ├── authd/           bubble-authd
│   ├── acl/             rpcd ACL JSON
│   └── uhttpd/          uhttpd config snippet
├── package/             OpenWRT package skeleton (Makefile, files/)
├── docs/                screenshots, threat-model deep dives
└── .github/workflows/   CI: build, lint, audit
```

## 10. Build & install

- Frontend: `pnpm build` produces `dist/` with hashed assets.
- Package: standard OpenWRT `Makefile` builds `bubbleui_<ver>_all.ipk`. Install via `opkg install`.
- Hardware test matrix (eventually): GL-MT3000 (Beryl AX), GL-MT2500 (Brume 2), generic ath79 device.

## 11. Open questions

1. **WebAuthn key material storage.** Where do we store registered credential public keys — UCI, or a small SQLite DB? UCI is the OpenWRT-native answer but is awkward for binary blobs.
2. **Setup-mode network.** Do we use the standard OpenWRT recovery `192.168.1.1`, or a less-collision-prone `192.168.111.1`?
3. **Firmware update flow.** Out of scope for v0, but we should not regress sysupgrade.
4. **Telemetry.** Default: none. Opt-in error reporting later, *only* over the configured VPN.

## 12. Milestones

- **M0 — this doc.** Design freeze, repo scaffold lands.
- **M1 — frontend skeleton.** Svelte+Vite app with mock RPC, all screens stubbed, Nerd Font wired in.
- **M2 — auth.** `bubble-authd` shell PoC against a real YubiKey on a Linux box (not router yet). Recovery code path tested.
- **M3 — ubus wiring.** Run on a real OpenWRT device. Hotel WiFi + travel SSID screens functional.
- **M4 — VPN + DNS.** WireGuard kill switch, DoH default. End-to-end on hardware.
- **M5 — packaging.** `.ipk`, install docs, first tagged release.
