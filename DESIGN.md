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
- Captive-portal detection and the firewall interaction it forces are the subject of §6.5; this section only handles the "scan, associate, get DHCP" mechanics.

### 6.2 WireGuard client + kill switch

- Import config: paste `.conf`, scan QR, or upload file.
- One-tap connect; status pill shows handshake age.
- Kill switch: dedicated `wg` firewall zone with `forward=REJECT`, LAN zone forwards only to `wg`. When `wg0` is down, no LAN→WAN forwarding exists — with one narrow, time-boxed, user-consented exception during captive-portal sign-in (see §6.5).
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

### 6.5 Captive portal × kill switch

§6.1 detects captive portals; §6.2 mandates that LAN→WAN forwarding is rejected whenever `wg0` is down. These contradict for one specific window: the user must clear the hotel portal *before* the tunnel can come up, but the kill switch is what blocks them from doing it.

The v1.0 resolution is a tightly-scoped, explicitly user-consented bypass — GL.iNet's "auto-detect and let me sign in" UX, with the safeguards GL.iNet skips.

#### Mechanism

1. **Detect early.** Right after `wwan` gets DHCP, before any WG handshake attempt, probe a hardcoded list of connectivity-check URLs (`detectportal.firefox.com`, `connectivitycheck.gstatic.com`, plus our own probe). Capture redirect-target IPs from the probe responses. Honor RFC 8910 (DHCP option 114) when present — modern networks announce the portal URL directly.
2. **Prompt explicitly.** UI shows a card with the detected portal target and a "Open sign-in window" button. Default state is closed; nothing opens silently. Cancel keeps the kill switch up.
3. **Open a narrow firewall hole.** On consent, `bubble-netd` adds an nftables rule allowing `lan → wwan` to the captured portal IP set, on TCP 80/443 only. Comment-tagged for auditability. All other LAN→WAN traffic stays blocked.
4. **Time-box.** 10-minute hard expiry, scheduled at rule creation. User can click "Close window now" to revoke early.
5. **Provide DNS during the window.** A scoped dnsmasq instance forwards LAN queries to the hotel-pushed DNS server, *only* during the window. Strict TTLs, no caching past the window. Closes when the window closes.
6. **Auto-close on success.** Background probe runs every 5 s through the open window. First probe success → drop firewall rule + DNS forwarder, bring up WG, status flips to "secured."
7. **Re-captivity.** Hotels often re-prompt every 24 h or after idle. Background probes detect this; the tunnel goes down, kill switch re-engages, UI re-prompts. *No auto-reopen* — explicit user click each time.

#### Visibility

While the sign-in window is open, a persistent yellow banner is shown across **every** screen of the UI (not only the WiFi pane), with countdown:

```
⚠ Sign-in window open — 7m 32s remaining.
   LAN→WAN allowed to 203.0.113.42 on TCP 80/443 only.   [ Close now ]
```

This is a security-relevant state; it must be impossible to forget about. Banner is also exposed via the LED on routers that have one (slow yellow blink).

#### Strict mode

Settings toggle: "Disable captive-portal sign-in window." When enabled, no firewall hole ever opens automatically. Captive portals must be cleared via a dedicated "Sign-in only" SSID (a future feature; documented as v1.x) or by manually disabling the kill switch for the duration. Default: off. Intended for trips where any LAN exposure is unacceptable.

#### MAC stability

WAN-side (STA) MAC defaults to **stable-per-SSID** (deterministic hash of SSID + per-trip salt), not OpenWRT's per-association randomization. Hotels remember our authorization across reboots within a trip; nothing carries across trips.

#### Architectural seam

The "where the user signs in" surface in `bubble-netd` is a pluggable interface. The v1.0 implementation routes the user's browser to the hotel portal via the firewall hole described above. A future `RouterProxySigningIn` implementation (v1.x exploration) could intercept the portal HTML server-side, rewrite links/forms to point back at BubbleUI, and execute the auth flow on the user's behalf — eliminating the LAN exposure window entirely. Detection logic, time-boxing, status surfacing, and auto-close are unchanged in either implementation.

#### Decisions pinned

- **Window duration:** 10 min default, user-configurable 1-30 min.
- **Probe targets:** Firefox + Google + a self-hosted endpoint, so we're not single-vendor-dependent. Probe interval during open window: 5 s.
- **MAC policy:** stable-per-SSID, not per-association randomized.
- **Banner placement:** every screen, not just WiFi.
- **Allowed ports during window:** TCP 80, 443 only. No DNS over UDP/53 to upstream — the scoped dnsmasq handles it locally.

#### v1.x roadmap

Router-as-portal-proxy: an HTML proxy that fetches and rewrites the portal page through BubbleUI's own UI, eliminating the LAN exposure window for the portals it can handle. Falls back to the v1.0 firewall-hole flow when the proxy can't handle a particular portal (JS-heavy SPAs, OAuth-style identity-provider redirects, etc.). Explicitly *not* a v1.0 commitment — explore if the v1.0 flow proves annoying on real trips.

### 6.6 Boot sequence and time bootstrapping

The reference hardware (§13) has no battery-backed RTC. On cold boot, the system clock sits at the kernel build date — effectively "the past." TLS validation against any cert with a `notBefore` after that date fails, which means **DoH cannot establish, all DNS dies, and the user sees no internet** until time is set. WireGuard itself is time-tolerant (it requires monotonic time, not correct time) so the tunnel survives bad clocks; DoH is the acute failure mode.

#### Bootstrap order

```
Boot
  ├─ 1. Restore last-known time from /etc/bubble/last-time
  │     clock = max(stored, kernel_build_date)
  │     guarantees: time is "approximately correct, never in the past"
  │
  ├─ 2. LAN up (192.168.8.1, dnsmasq for local resolution)
  │     user can reach BubbleUI immediately
  │     kill switch fully closed; no LAN→WAN forwarding
  │
  ├─ 3. User opens BubbleUI on a device
  │     SPA POSTs Date.now() to /api/time/sync
  │     router accepts if within ±5 min of stored time, else prompts user
  │     time is now correct; persisted to flash
  │
  ├─ 4. WAN up (associate with hotel SSID, DHCP)
  ├─ 5. Captive-portal sign-in window if needed (§6.5)
  ├─ 6. DoH up (TLS validation works)
  └─ 7. WG up; status pill goes secured
```

#### Why browser-supplied time, not NTP

The user's laptop already has correct time — generally NTS-validated and OS-corrected. Borrowing it via the browser:

- requires zero network bootstrap on the router (no chicken-and-egg);
- requires no NTP server allowlist or IP pinning;
- requires no NTS implementation;
- avoids "hostile hotel pushes wrong time" attacks (the laptop's clock isn't on hotel WiFi);
- is more trustworthy than NTP from a random pool server.

NTP becomes a **nice-to-have background sync** for unattended reboots, not a critical path. Runs once per hour via `busybox ntpd` if a network is reachable; failure is silent.

#### Browser-time accept/prompt logic

- **Auto-accept** if `|browser_time − router_time| < 5 min`. Just write to flash and persist.
- **Prompt** otherwise:

  ```
  ⚠ Router clock differs from your device by 2 days.
     Your device says: 2026-05-09 14:32:18 UTC
     Router thinks:    2026-05-07 21:14:02 UTC
     [ Sync to device clock ]   [ Keep router clock ]
  ```

- "Keep router clock" path is for the rare case where the user knows their device's clock is wrong (loaner laptop, intentionally time-shifted test device).

#### Persistence

- Write `/etc/bubble/last-time` every 5 min during normal operation.
- Write on clean shutdown via init script.
- On boot, clamp to `max(stored, build_date)` so a regressing clock can never make WG drop or certs appear future-invalid.

#### BubbleUI's own HTTPS cert

Self-signed, broad validity:

- `notBefore = 2020-01-01`, `notAfter = 2099-01-01`. Time-set state of the router doesn't affect cert validity.
- Generated once at provisioning, stored in `/etc/bubble/ui.pem`.
- CN = `bubble.local`, SAN includes the LAN IP (`192.168.8.1`).
- Browser warns once on first connect; user accepts the exception. Subsequent visits are silent.

A future v1.x feature could ship a per-router cert installable into the user's trust store via QR code, eliminating the warning. Out of scope for v1.0.

#### Decisions pinned

- **Time source:** browser-supplied, primary. NTP is fallback, optional, background-only.
- **Tolerance:** ±5 min for silent accept, otherwise prompt.
- **Persistence cadence:** every 5 min during operation, plus on clean shutdown.
- **Cert strategy:** self-signed broad-validity for v1.0; per-router-installable for v1.x.

## 7. Frontend

### 7.1 Stack

- **Svelte 5** + **Vite** + **TypeScript**.
- No router library; a 60-line hash-router suffices for ~6 screens.
- No UI library. Hand-rolled components, CSS variables for theming.
- State: Svelte stores. No Redux/Pinia/etc.
- API client: a single `rpc.ts` module wrapping `fetch` to `/ubus`.

### 7.2 Typography

We're using a **Nerd Font** as both UI and icon font. This avoids shipping an icon set (Lucide/Feather are ~30-50 KB even tree-shaken) — instead we render glyphs like `` (wifi) directly.

**Default: CaskaydiaCove Nerd Font Mono** (Cascadia Code patched, mono variant — colloquially "CaskaydiaMono").

- Same font Omarchy shipped as its default until v3.2.0 — friendly, readable, distinctive curly italics. Reads as "fun" rather than "enterprise."
- Cascadia Code is Microsoft-maintained; the Nerd Font patch tracks upstream releases.
- Subsetted to Latin + the icon glyphs we actually reference, shipped as WOFF2. Target font payload < 60 KB.
- Ghostty rendering issues (the reason Omarchy moved away from it) don't apply to us — we render in a browser, not a terminal emulator.

**Alternates documented** for the user to swap via a CSS variable: JetBrainsMono Nerd Font, Maple Mono NF, Monaspace Neon (`MonaspiceNe`), CommitMono Nerd Font.

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
- **Hardware:** GL-AXT1800 (Slate AX) running **vanilla OpenWRT 23.05+**. GL.iNet's stock firmware is explicitly out of scope. See §13.

## 11. Open questions

1. **WebAuthn key material storage.** Where do we store registered credential public keys — UCI, or a small SQLite DB? UCI is the OpenWRT-native answer but is awkward for binary blobs.
2. **Setup-mode network.** *Resolved:* `192.168.8.1` (the GL.iNet hardware default; minimizes collisions with hotel/home networks that almost universally use `192.168.0/1.x`). See §6.6.
3. **Firmware update flow.** Out of scope for v0, but we should not regress sysupgrade.
4. **Telemetry.** Default: none. Opt-in error reporting later, *only* over the configured VPN.
5. **VPN provider strategy** *(partially resolved)*.
   - **v1.0:** WireGuard-only, but as a *pool of saved configs* with active probing — user imports N `.conf` files once, the daemon TCP-connects to each endpoint at connect time and picks the lowest RTT. Per-row enable toggle, "stale" indicator when a config stops handshaking, automatic fail-over to next candidate on three-strike failure. This delivers the "Quick Connect" UX from the Proton/Mullvad apps without an API integration, and the prober/selector code is exactly what the v1.1 provider plugins will reuse.
   - **Post-v1.0 roadmap:** ProtonVPN account login (SRP auth + dynamic WG provisioning + live server list — see §11.5b). Cloudflare WARP fallback via `wgcf`-generated configs. Mullvad / iVPN as additional plugins. All of these become "config sources" feeding into the same pool + prober already shipping in v1.0.
   - **Plugin shape for `bubble-vpnd`:** the daemon grows a `provider` interface (`list_servers → connect(target) → disconnect → status → pick_fastest(filters)`) so each post-1.0 provider is additive, not a rewrite. The v1.0 WG-pool implementation is the reference plugin.

## 12. Milestones

- **M0 — this doc.** Design freeze, repo scaffold lands.
- **M1 — frontend skeleton.** Svelte+Vite app with mock RPC, all screens stubbed, Nerd Font wired in.
- **M2 — auth.** `bubble-authd` shell PoC against a real YubiKey on a Linux box (not router yet). Recovery code path tested.
- **M3 — ubus wiring.** Run on a real OpenWRT device. Hotel WiFi (including the captive-portal sign-in flow per §6.5) + travel SSID screens functional.
- **M4 — VPN + DNS.** WireGuard kill switch, DoH default. WG runs as a *pool of saved configs* with TCP-connect probing and `Connect to fastest` as the default action; auto fail-over to the next candidate on handshake failure. End-to-end on hardware.
- **M5 — packaging.** `.ipk`, install docs, first tagged release (**v1.0**).
- **M6+ — provider plugins.** ProtonVPN account login (SRP + dynamic WG provisioning), Cloudflare WARP fallback via `wgcf`, additional providers as community asks. Each one is a new source feeding the same pool + prober shipped in M4.

## 13. Hardware target

**Reference device: GL.iNet GL-AXT1800 (Slate AX), running vanilla OpenWRT.**

Chosen because it's the cleanest VPN-capable travel router in its segment: vanilla OpenWRT support is mature (`qualcommax/ipq60xx` target), the USB 3.0 port is well-suited for an always-attached YubiKey, and the WiFi 6 dual-radio config supports simultaneous AP+STA on different bands without contention.

### 13.1 Specs

| | |
|---|---|
| SoC | Qualcomm IPQ6000 (4× ARM Cortex-A53, ARMv8) |
| RAM | 512 MB DDR3L |
| Flash | 128 MB NAND |
| WiFi | 802.11ax dual-band 2×2 — 574 Mbps @ 2.4 GHz, 1201 Mbps @ 5 GHz |
| Wired | 1× Gigabit WAN, 1× Gigabit LAN |
| USB | 1× USB 3.0 type-A (always-attached YubiKey lives here) |
| Power | USB-C, 5 V / 3 A |
| LED | 1× multi-color (top) |
| RTC | none — see §6.6 |

### 13.2 Firmware base — vanilla OpenWRT only

**Vanilla OpenWRT 23.05 or later. GL.iNet's stock firmware is explicitly out of scope and not supported.**

Reasons, not tradeoffs:

- GL.iNet's firmware is a heavily customized OpenWRT fork with uneven update cadence. Vanilla gets reliable security updates from upstream.
- We don't want to inherit GL.iNet's UI, their bundled apps, their telemetry, or their WAN-side cloud features.
- Portability: anything we build on vanilla works on every other OpenWRT-supported device with comparable resources, which is good hygiene even though we only target one device today.
- The AXT1800's hardware quirks (Mode switch, LED, button) become generic GPIOs we bind ourselves in `bubble-hwd`. Small upfront cost, total control.

### 13.3 Resource budgets

| | |
|---|---|
| Frontend bundle (HTML+JS+CSS+font) | < 400 KB target, ~200 KB realistic |
| Each Go daemon, stripped | 3-6 MB |
| Total BubbleUI install footprint | < 25 MB on flash |
| BubbleUI RAM at idle (all daemons) | < 50 MB |

Leaves comfortable headroom for OpenWRT, dnsmasq, hostapd, wireguard tools, and trip configurations on a 128 MB / 512 MB device.

### 13.4 Radio plan

- **Travel SSID (AP):** 5 GHz default. Less congested in hotels, faster, supports more devices.
- **Hotel uplink (STA):** 2.4 GHz default. Better penetration, more universally available.
- User can swap in settings if a particular trip's hotel is 5 GHz only.

### 13.5 LED behavior

| State | LED |
|---|---|
| Setup mode | solid blue |
| Booting | white pulse |
| Tunnel up, secured | solid green |
| Captive-portal sign-in window open (§6.5) | slow yellow blink |
| Tunnel down, kill switch active | slow red blink |
| Hardware fault / YubiKey expected but missing | fast red blink |

### 13.6 Portability

Hardware-touching code (LED, GPIO, USB enumeration paths) lives in a single `bubble-hwd` adapter. Supporting another OpenWRT device is a matter of writing a new adapter, not rewriting the daemons. But the AXT1800 is the *only* device tested or supported in v1.0; everything else is best-effort and explicitly unsupported.
