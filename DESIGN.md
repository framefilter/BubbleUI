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

- A full LuCI replacement. We expose a focused subset. LuCI is **not shipped** (see §5.1): it is a password-based admin surface that would bypass our WebAuthn-only auth. A power user can `apk add luci` on demand, as a deliberate opt-in they understand weakens the device's security posture — a user choice, not a default and not a recovery mechanism.
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
|  (UCI, net,  |  |  (Go)           |
|   wireless,  |  |  - WebAuthn     |
|   firewall)  |  |    verification |
|              |  |  - issues rpcd  |
|              |  |    sessions     |
+------+-------+  +--------+--------+
       |                   |
       v                   v
   UCI / netifd       (no USB code path)
```

**Why this shape**

- Reusing `ubus`/`rpcd` means we inherit OpenWRT's existing auth model (sessions, ACL groups, audit logs) and don't ship a parallel privilege boundary.
- The auth helper is the *only* component that talks to USB. Everything else stays declarative UCI calls.
- A clean uhttpd → rpcd path lets us drop in mTLS or a future binary auth daemon without changing the SPA.
- Hardware-touching daemons (`bubble-hwd`, the `wg-quick` Connector, the nftables Applier) consult **UCI / `/etc/board.json` first, sysfs second** — see §14. This is what lets one .ipk cover every Tier-2 vanilla-OpenWRT device without per-board code on our side.

## 5. Authentication

### 5.1 Decisions

- **Scope:** *all* UI and SSH access requires a hardware-backed credential. No anonymous status page, no password fallback, no remote root.
- **No passwords anywhere.** Not for the web UI, not for SSH. Authentication is purely hardware-backed.
- **Factor: WebAuthn (FIDO2).** A registered browser-side authenticator — Touch ID, Windows Hello, an Android device, a plugged-in FIDO2 hardware key (YubiKey 5+, SoloKey, etc.). Multiple devices can be registered; each is its own credential, and any registered credential is sufficient.
- **No router-attached hardware key.** Earlier drafts described a co-equal "YubiKey on router USB" path via HMAC-SHA1 challenge-response (`ykchalresp`). That path has been removed: the upstream `yubikey-personalization` / `ykpers` package was dropped from openwrt/packages on 2025-11-22, so 25.12.x has no supported way to ship `ykchalresp` on the device. The HMAC-SHA1 model is also a strict security downgrade vs. FIDO2 (symmetric shared-secret vs. asymmetric per-credential). The future restoration of HW-bound at-rest wrapping uses the FIDO2 `hmac-secret` extension on a registered WebAuthn credential — see §11.8.
- **Recovery:** a single 128-bit recovery code shown once at first registration, BLAKE2s-hashed on disk, single-use, regenerable from settings (the old code is invalidated).
- **No password recovery, no email reset, no support backdoor.** If the user loses every registered credential AND the recovery code, the only path is factory reset and re-provision. This is the right outcome for a travel router — the device holds little irreplaceable state.
- **No LuCI by default.** LuCI's rpcd/password login is a parallel auth surface that would defeat the WebAuthn-only rule above, so it is not shipped. A power user may `apk add luci` on demand to get full LuCI — an explicit, out-of-band opt-in that knowingly weakens this posture. It is a user choice, not a backdoor we ship, and not a recovery path (it requires a working uplink). See §2 and §14.5.

### 5.2 Provisioning flow (first boot)

1. Router boots into setup mode on `192.168.8.1`. Firewall blocks WAN until setup completes.
2. Wizard requires the user to register **at least one** WebAuthn credential:
   - Standard `navigator.credentials.create()` with the user's choice of platform or cross-platform authenticator. Public key persisted to `/etc/bubble/credentials.db`.
3. On the first credential registration, the server mints a 128-bit recovery code, returns it to the wizard once, and stores only its BLAKE2s hash. The wizard **requires the user to type it back** to confirm preservation.
4. Setup mode exits; future access requires a registered credential.

### 5.3 Login flow

1. SPA requests a session.
2. `bubble-authd` issues a WebAuthn challenge listing all registered credential IDs (`POST /auth/webauthn/login/begin`).
3. Browser prompts user via the FIDO2 device — Touch ID, Windows Hello, plugged-in security key, etc.
4. User taps / authorizes; browser signs the assertion.
5. Daemon verifies signature against the stored credential public key, constant-time (`POST /auth/webauthn/login/finish`).
6. On match, mint session token, set cookie `HttpOnly; Secure; SameSite=Strict`.

### 5.4 Recovery flow

1. User clicks "Lost my keys" on the login page.
2. Enters the printed recovery code.
3. Server checks `BLAKE2s(code)` against the stored hash, constant-time.
4. If valid, the code is **burned** (replaced with random bytes), all registered credentials are wiped, the device returns to setup mode, and the user re-provisions from scratch.
5. **Trip configs survive** — WG configs, SSID names, DNS provider, etc. are not bound to auth and are preserved across recovery. Only credentials and the recovery code are reset.

There is no other recovery path. Lose all credentials *and* the recovery code → factory reset. This is intentional and stated up front.

### 5.5 At-rest protection of router-side secrets

With WebAuthn-only auth (§5.1), the credentials store holds only **public** material: each registered credential's COSE public key, credential ID, and label. Public keys are public by definition; there is no symmetric secret on the device to protect at rest, and so the wizard does not derive or persist any HW-bound wrap key.

This is a *narrower* posture than earlier drafts described — the older "self-wrap `S` with HMAC-SHA1(S, fixed-challenge)" pattern is gone with the router-attached YubiKey path. Any future secret that should be wrapped against a hardware token (e.g. cached WireGuard private keys, future session-rebind tokens) goes through the FIDO2 `hmac-secret` extension on a registered WebAuthn credential rather than a router-side HMAC oracle. See §11.8 for the open work item.

Recovery codes are stored as BLAKE2s hashes only; the plaintext is shown to the user exactly once and never persisted on the device (§5.4).

### 5.6 What this does *not* protect against

- An attacker with physical access to both the router and a registered key.
- An attacker who has both a user's laptop *and* the means to satisfy its registered authenticator (biometric, PIN, plugged-in key).
- A YubiKey with a known-weak slot 2 secret pre-provisioned by a hostile party. Mitigation: always provision from setup mode on a fresh router.
- An attacker with the printed recovery code. Mitigation: store the code separately from the router and treat it as a backup credential, not paperwork to file with the device manual.

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

- Per-trip SSID name and password.
- `isolate=1` on the AP by default.
- Optional guest VLAN with its own DHCP scope and zero LAN access.
- "Forget this trip" wipes the SSID, password, leases, and ARP cache.

Wifi security defaults are the subject of the next subsection and apply
to **every** BubbleUI-managed AP — the Travel SSID, the factory SSID
used at first boot, and any future "guest" / "kids" / IoT SSID the
product grows. The audience (privacy-conscious, low-to-middling tech
ability) should not be expected to reason about cipher suites or roll
their own posture; the defaults need to be right out of the box.

### 6.3a Wifi security posture (BubbleUI-as-AP)

#### Allowed encryption modes

| Mode | UCI `encryption` | Default? | Notes |
|---|---|---|---|
| **WPA3-Personal (SAE)** | `sae` | **Yes** | Default for every new SSID. Mandates PMF=required. |
| **WPA3/WPA2 transition** | `sae-mixed` | Opt-in | "Compatibility mode." Same SSID accepts both SAE and PSK clients. PMF=optional. Use only when a needed client (older Android, legacy laptops, kids' tablets) cannot do WPA3. |
| **WPA2-Personal (PSK, AES-CCMP)** | `psk2+ccmp` | Opt-in | Only for SSIDs the user explicitly downgrades. PMF exposed as a separate UI toggle (`ieee80211w`: 0/1/2). |

The UI surfaces these as three radio buttons per SSID, with WPA3-SAE pre-selected. The transition-mode option warns inline that it widens the downgrade surface; the WPA2-only option warns more strongly and asks for an explicit confirm.

#### Refused outright (no UI affordance, no UCI plumbing exposed)

- **WPS** in any form (`wps_pushbutton`, `wps_label`, AP PIN). The WPS PIN protocol is broken (Reaver, Pixie Dust) and the push-button variant adds a 2-minute window where any nearby station can register. There is no path to enable it from the UI.
- **WEP** in any form (`wep-open`, `wep-shared`, `wep+open+shared`). Trivially recovered key. The UI never lists it; the daemon refuses to write it even if a config import tries.
- **Open** SSIDs (`none`). Not a default. A future "captive guest hotspot" use case might justify a flag-gated escape hatch — that's a separate design conversation, not v1.0.
- **WPA1 / TKIP** (`psk`, `psk+tkip`, `psk-mixed+tkip`). Deprecated; chosen-plaintext + MIC attacks on TKIP are practical. Same refusal posture as WEP.

#### Protected Management Frames (PMF / 802.11w)

PMF protects deauth/disassoc/action frames against forgery — without it, anyone in range can knock clients off the AP with a single broadcast frame. PMF semantics by mode:

- **WPA3-SAE:** PMF is *required* by the WPA3 spec. We pin `ieee80211w=2`. Not a toggle.
- **WPA3/WPA2 transition (`sae-mixed`):** PMF defaults to *required* but downgrades to optional per-client at association time, so legacy clients still associate. We pin `ieee80211w=1` and document this as an inherent property of transition mode — if a user can't tolerate it, they should pick WPA2-only and turn PMF on explicitly.
- **WPA2-Personal:** PMF is *optional* in the standard. Where the OpenWRT build supports it (it does on 25.12.x with `wpad-basic-mbedtls` and on `wpad-mesh-mbedtls`), the UI exposes a per-SSID toggle (`ieee80211w`: 0 disabled / 1 optional / 2 required). Default for new WPA2-only SSIDs is `1` (optional) so legacy clients still associate, with the UI nudging "consider Required" inline.

The driver/firmware on the AXT1800 (ath11k, ipq60xx) supports PMF in all three modes; older targets may not. The hardware abstraction in §14's quirks registry surfaces a `pmf_supported: bool` per radio so the UI can hide the toggle on devices that genuinely can't do it rather than offering a setting that silently breaks association.

#### Factory wifi (first-boot / post-reset)

The factory SSID is the gateway to the bootstrap captive portal (§6.8). Its security properties matter — anyone who can associate to it can hit the unauth `/api/bootstrap/*` endpoints.

- **Encryption:** WPA3-SAE only. No transition mode at factory; a user who needs WPA2 transition can opt in *after* setup completes from the SPA. The pre-setup audience shouldn't have to navigate the tradeoff.
- **Password:** per-device unique, generated at first boot from a CSPRNG, formatted as 5 dictionary-derived words for typing without errors (think Diceware, but printed on the device label rather than memorized). Minimum entropy ≥ 60 bits. *Never* derived from MAC, serial, or any other on-device material — those are externally observable.
- **Label printing for the audience:** since v1.0 testing-phase images are flashed onto hardware the maintainer ships to early testers, the factory wifi password gets generated and printed onto a sticker the maintainer applies to the device. This is friction we accept for the test phase; the long-term distribution model is a separate conversation (see §10.4).
- **SSID:** generic, non-identifying. Not `BubbleUI-AXT1800-A4F2` (leaks hardware + serial-ish info to anyone scanning); not the user's name. Default is `BubbleUI` with a small random suffix for collision avoidance, changeable in the wizard.

#### What this is not yet covered by

- **WPA3-Enterprise.** Not relevant to the audience (no RADIUS server in the threat model).
- **Per-client randomized PSKs / OWE.** Out of scope for v1.0 — adds UI complexity for marginal benefit on a travel router. Revisit if a clear demand emerges.
- **Roaming / 802.11r FT.** Travel routers aren't roaming endpoints in any meaningful sense.

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

### 6.7 First-boot wizard

The wizard runs in setup mode (`192.168.8.1`, WAN blocked). It walks the user from a freshly flashed device to a working BubbleUI in roughly three minutes. State persists server-side; closing the browser mid-wizard is safe; reboot during the wizard returns to the same state.

#### Steps

1. **Welcome.** "BubbleUI setup. About 3 minutes."
2. **Time check.** Silent if the browser's clock and the router's persisted clock agree within 5 min (§6.6); otherwise prompts.
3. **Register a security key** *(required, ≥1)*. WebAuthn from this browser — Touch ID, Windows Hello, an Android device, or a plugged-in FIDO2 hardware key (YubiKey 5+, SoloKey, etc.). The credential ceremony runs in the browser; the router stores only the resulting public key. Additional credentials can be registered later from settings.
4. **Recovery code** *(required)*. Generated server-side, displayed once, **typed back to confirm preservation**. The "I've written it down" path is intentionally not just a click — the recovery code is the *only* fallback if all credentials are lost (§5.4).
5. **WireGuard configs** *(optional)*. Drag-drop or paste any number of configs into the pool. Skippable; addable later from VPN settings. Background prober and "fastest" selection apply automatically once the pool has ≥1 entry.
6. **Uplink** *(optional)*. "Connect this router to the internet now, or skip and set up at the hotel."
   - WiFi (scan + pick + password)
   - Wired (instructions to plug WAN port)
   - Skip
7. **SSH access** *(optional)*. Off by default. To enable, paste an SSH public key:
   - Strongly recommended: `ssh-keygen -t ed25519-sk -O resident -f ~/.ssh/bubble_sk` (FIDO2-backed; touching the security key is required for every connection).
   - Plain `ed25519` keys accepted but not recommended.
   - Password auth and root login are never offered.
   - SSH binds only to the LAN side; never reachable from WAN.
   Skippable; can be enabled later from settings.
8. **Done.** Brief status snapshot. Setup mode exits; firewall transitions to its normal posture.

#### Setup-mode exit conditions

Setup mode is considered complete when:

- ≥1 security credential is registered, **and**
- the recovery code has been displayed *and* typed back successfully.

Steps 5, 6, and 7 are all optional — users who skip them land in a perfectly usable BubbleUI that simply hasn't connected to anything yet, has no WG configs, and has no SSH enabled.

#### Resumability

Wizard state persists in `/etc/bubble/setup-state.json`. Closing the browser mid-wizard returns to the same step on next visit. Wizard step N is idempotent — re-running it has no side effects beyond what it would do the first time.

#### Wizard skip ≠ feature missing

Anything skipped in the wizard is reachable from the regular UI. The wizard is a convenience layer for first-time setup; it is not the only path to any feature.

#### SSH server choice

Default `dropbear` configured with `PasswordAuth no`, `RootLogin no`, key-based only. If `dropbear` proves to lag on `sk-*` key support, swap to `openssh-server` (~1 MB extra footprint). Decision deferred to M2 testing on real hardware.

### 6.8 Roaming uplink recovery (no-upstream captive portal)

After the first-boot wizard (§6.7) has run, the router is configured but mobile — the user takes it to hotels, cafés, friends' houses. Each new venue is a "no remembered AP in range" situation. Asking the audience (low-to-middling tech ability; see project intent) to SSH in or remember an admin password just to point the router at a new wifi defeats the product. §6.8 covers what happens instead: when the router has no working upstream, BubbleUI presents an **unauthenticated** wifi-join page to any device on its LAN, surfaced via the OS-native captive-portal mechanism.

This is distinct from §6.5 (kill-switch's interaction with a hotel's own captive portal — router-as-client) and §6.7 (the first-boot wizard, which is a one-time superset of this UX). §6.8 is the steady-state "router has no internet and needs help getting some" flow.

#### State machine

A new daemon `bubble-bootstrapd` owns the state. Four states:

- **CONNECTED.** WAN has a route to the internet (verified via the connectivity probe described below). All API auth is enforced; bootstrap unauth endpoints 401.
- **NO_UPSTREAM.** No working WAN AND no remembered AP visible in the last successful scan. nftables redirects LAN HTTP egress to the BubbleUI nginx vhost; dnsmasq serves wildcard answers (LAN IP) including for the captive-portal probe domains; the three bootstrap endpoints below answer without auth.
- **JOINING.** User submitted a join via the bootstrap UI; daemon is reconfiguring wpa_supplicant via `bubble-netd` and waiting for IP + connectivity. Same redirect/dnsmasq/auth posture as NO_UPSTREAM until JOINING resolves either way.
- **STALE_RESCAN.** Scan call failed (driver/firmware blip — known intermittent on the AXT1800's ath11k). Stay open, mark the scan list as stale in `/api/bootstrap/status`, retry on a backoff. Does *not* bounce to CONNECTED, since "we couldn't scan" is not "we're online".

Entry: `CONNECTED → NO_UPSTREAM` when the connectivity probe has failed for ≥30s AND a fresh scan returns zero overlap with the saved-networks set. The 30s debounce keeps a quick WAN flap (cable bump, brief AP roam) from bouncing the LAN into captive-portal mode.

Exit: `NO_UPSTREAM | JOINING → CONNECTED` when the connectivity probe succeeds. The probe is described below — we deliberately don't trust the OS captive-portal probe domains here because an AP we just joined could intercept them, and "OS thinks we're online" is the wrong signal for "we, the router, are actually online".

NO_UPSTREAM is a *transient operational state*, not a persistent privileged mode. Factory-reset is a separate, deliberately heavier path (button-hold; documented elsewhere when we get to §13.x).

#### What the user sees

1. Phone connects to BubbleUI's wifi using the WPA2/3 password printed on the device label (per §6.5 travel-SSID model). This is the only credential required at this stage.
2. iOS / Android / macOS / Windows / Chrome OS each run their captive-portal probe on association. With `bubble-bootstrapd` in NO_UPSTREAM, those probes get intercepted (dnsmasq + nftables); the OS classifies the network as "captive" and pops the standard "Sign in to network" notification.
3. Tapping the notification opens the OS captive web-view to BubbleUI's `/bootstrap` page (HTTP, the router's LAN IP — `192.168.8.1` per §6.6). No certificate prompts, because we don't try to MITM TLS.
4. The page shows: a live scan list (SSID, signal bars, security type, ★ for remembered), a "join other network" form (for hidden SSIDs), and a status indicator. No admin surface. No login.
5. User picks an AP, enters the password if needed, taps Join.
6. Page polls `/api/bootstrap/status`; on success it shows "connected — continue to BubbleUI" linking to the authenticated UI at `https://bubble.lan` (or whatever §6.6 nails down). On failure, it returns to the scan list with a reason ("wrong password", "AP disappeared", "DHCP timeout").

The crucial property: a fresh-out-of-the-airport user holding their phone never sees a login screen. They see wifi options and they pick one.

#### Unauth surface — explicit allowlist

The unauthenticated API surface in NO_UPSTREAM / JOINING is exactly three endpoints. Everything else 401s in every state. The auth middleware checks state to *skip* auth on these three; it does **not** elevate any other endpoint's privileges or expose any new ones.

- `GET /api/bootstrap/scan` — channel, SSID, RSSI, security mode, `remembered: bool`. Same fields `iwinfo scan` already exposes to anyone with physical proximity; no new leak.
- `POST /api/bootstrap/join` — body `{ssid, security, key?}`. Returns `{join_id}`. Body is opaque to the daemon beyond passing it to `bubble-netd`'s scan-and-join helper (single source of truth shared with §6.7 step 6).
- `GET /api/bootstrap/status` — `{state, last_scan_age, active_join?: {id, progress, error?}}`.

What these endpoints CANNOT do (defense in depth — the daemon refuses, not just the middleware):

- Touch firewall rules outside the `bubbleui_bootstrap` named chain.
- Read or write any credential, recovery code, or session.
- Read or write VPN configs, DNS settings, MAC privacy settings, hostname.
- Read system logs, config files outside the wpa_supplicant ssid+psk it's writing.
- Trigger reboot, sysupgrade, or any sysctl change.

#### Threat surface and the button-press hardening

Active threat in NO_UPSTREAM: a person on the LAN — meaning someone who has the device's WPA2/3 password — can initiate a join to an AP they control, redirecting the router's uplink. The product's §3 threat model already excludes attackers with physical access to the device, so the realistic case is "someone the user gave wifi access to, acting maliciously while the router is in a transient no-upstream state". Narrow.

Two things keep this narrow rather than wide:

- The factory wifi password is unique per device (printed on the label). Default deployment is not an open wifi.
- The post-join uplink goes through every normal BubbleUI control plane on transition back to CONNECTED — VPN kill-switch re-arms, encrypted DNS re-engages, the captive-portal-x-killswitch flow (§6.5) intercepts any hotel portal. A malicious uplink doesn't bypass any of that; it just gets the user back to a state where the rest of the product is doing its job.

For users whose threat model includes "someone I gave wifi access to may try to attack me on the LAN":

**Settings → Security → "Require physical button press for wifi-join in roaming mode."** *(off by default)*

When on, `POST /api/bootstrap/join` returns `409 button_press_required` and the daemon arms a 30s window. The user must press the AXT1800's hardware button (mapped via §14's quirks registry — the reset button is the default GPIO; the side switch is also exposed and configurable). LED behavior during the window follows §13.7's "awaiting confirmation" pattern: distinct, not the same blink as boot or activity.

Off by default because adding a physical step is friction the audience can absorb at first-boot (they're holding the device anyway) but not necessarily at "I just sat down at a coffee shop." The toggle is for users who deliberately want the friction.

#### Connectivity probe

The probe is the signal that drives CONNECTED ↔ NO_UPSTREAM. Three properties we want:

- Doesn't lie when the local AP intercepts well-known captive-portal domains.
- Doesn't make BubbleUI a notable third-party-request source for big-tech telemetry surfaces.
- Survives the third-party host going away.

Compromise for M3: HTTPS GET to `https://detectportal.firefox.com/success.txt` with cert pinning to Mozilla's known CA chain, 5s timeout, expect literal `success` body. Mozilla has the least-bad privacy posture of the OS-probe operators. The pin means an MITM upstream can't fake "we're online". Failure modes (cert mismatch, body mismatch, timeout, DNS NXDOMAIN) all map to "not connected".

This is a deferred decision per §11.x — see entry added there. A self-hosted probe URL would be ideal but means we operate infra and that infra becomes a privacy-sensitive request log. Multi-probe-with-quorum is the likely landing spot; M3 ships single-probe-with-pin.

#### Interaction with other features

- **§5 Authentication.** §6.8 is the *only* state where any endpoint bypasses auth, and the bypass is endpoint-allowlisted, not blanket. The decision to be unauth here is justified by "the user hasn't yet had the chance to authenticate at this venue's network reachability, so requiring it is a deadlock," not by convenience.
- **§6.2 VPN kill-switch.** Suspended in NO_UPSTREAM and JOINING — there's no upstream to kill-switch, and clients in NO_UPSTREAM need DNS reachable to the captive-portal page. Re-armed atomically on the CONNECTED transition (before the nftables redirect rules come down, so clients can't briefly route outside the tunnel).
- **§6.4 Encrypted DNS.** Disabled in NO_UPSTREAM (no upstream resolver reachable). dnsmasq answers locally. Re-enabled on CONNECTED.
- **§6.5 Captive portal × kill-switch.** Distinct flow. §6.5 fires *after* §6.8 has joined an upstream that itself has a captive portal. Order: §6.8 gets the L2/L3 association, then §6.5 carves the portal-clearance hole, then normal kill-switched routing resumes.
- **§6.7 First-boot wizard.** Strict ordering: if the wizard has not completed (setup-state in `/etc/bubble/setup-state.json` is non-empty), `bubble-bootstrapd` does not enter NO_UPSTREAM regardless of network state — the wizard's setup mode is already a superset of bootstrap (it includes wifi-join in step 6) plus the credential ceremony. NO_UPSTREAM is only ever entered after setup-mode has exited.
- **§14 Hardware abstraction.** The button-press hardening uses §14's quirks registry to know which GPIO is the user-configurable button on this device. Defaults to "reset" on AXT1800; configurable per device.

#### Implementation sketch

- **New daemon: `bubble-bootstrapd`** (Go, ~300 LOC estimated). Owns the state machine. Inputs: `network.interface` ubus events, periodic `iwinfo scan` results via `bubble-netd`, connectivity probe goroutine, button-press events from `bubble-hwd`. Outputs: state file (`/var/run/bubble/bootstrap-state`), nftables ruleset transitions, dnsmasq conf-snippet swaps, the three `/api/bootstrap/*` endpoints.
- **nftables.** A named chain `bubbleui_bootstrap` is flushed and rebuilt atomically on state transitions. In NO_UPSTREAM / JOINING: DNAT TCP 80 from LAN to the BubbleUI nginx vhost on `192.168.8.1`; drop or REJECT TCP 443 from LAN (forces the OS into captive-mode rather than producing cert errors); no NAT on UDP 53 because dnsmasq already binds it.
- **dnsmasq.** Two named conf snippets, both shipped in the package: `bootstrap-on.conf` (wildcard `address=/#/192.168.8.1`) and `bootstrap-off.conf` (empty). The daemon `mv`s into `/tmp/dnsmasq.d/bootstrap.conf` and SIGHUPs dnsmasq on transition.
- **Frontend.** New `/bootstrap` route in the Svelte app, no auth guard. Reuses the scan-list and join-form components built for §6.7 step 6 — single set of components, two entry points.
- **`bubble-netd`.** Gains a `Bootstrap` ubus method exposing scan + join helpers, gated to only respond to `bubble-bootstrapd` (peer cred check on the ubus socket). The wizard and the bootstrap daemon both go through this method, so the wifi-join logic lives in exactly one place.

#### Open question (added to §11)

The connectivity probe URL — see §11.7.

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
| `bubble-authd` | Go | WebAuthn registration / assertion verification, recovery-code burn, session minting |
| `bubble-rpcd-acl` | JSON | ACL files declaring exactly which `ubus` paths the UI may call |
| `bubble-uhttpd-conf` | uhttpd config | Serves SPA, terminates TLS, proxies `/ubus` and `/auth` |
| `bubble-setup` | shell | First-boot wizard helper (§6.7), drives provisioning |
| `bubble-hwd` | Go | Hardware adapter — LED, GPIO, USB enumeration. Reference impl targets the AXT1800; new devices add a new adapter (§13.6) |

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

### 10.1 Distribution model — pure `.ipk`

BubbleUI ships as a single OpenWRT package (`.ipk`) per target
architecture. The user comes in with a working vanilla OpenWRT 23.05+
install (which they did themselves via the standard `sysupgrade`
flow), copies the right `.ipk` to the device, and runs:

```sh
opkg install /tmp/bubbleui_<arch>.ipk
```

That's the whole install. Post-install, the package's
`/etc/uci-defaults/bubbleui` runs once on first boot to:

- generate the self-signed UI cert (DESIGN §6.6 — broad-validity so
  wrong-time-on-boot doesn't break the UI);
- open TCP 80/443 in the LAN firewall zone via a named UCI rule
  (idempotent on re-run);
- enable + start the four daemons via procd.

The user opens `https://<router-ip>/` in a browser, accepts the
self-signed cert exception once, and lands on the §6.7 wizard.

### 10.2 What the package installs

| Path | Contents |
|---|---|
| `/usr/sbin/bubble-{authd,vpnd,netd,hwd}` | Cross-compiled static Go daemons (one per arch). |
| `/usr/share/bubbleui/` | Pre-built SPA dist (HTML+JS+CSS+font), served by nginx. |
| `/etc/init.d/bubble-*` | procd init scripts; respawn on crash, reload on UCI change. |
| `/etc/config/bubbleui` | UCI defaults read by every daemon at startup. |
| `/etc/uci-defaults/bubbleui` | First-boot one-shot (see §10.1). Deletes itself after success. |
| `/etc/nginx/conf.d/bubbleui.conf` | Reverse proxy + TLS termination. |

State directories (`/etc/bubble/credentials.db`, `/etc/bubble/vpn.db`,
the cert pair) are listed as `conffiles` so `opkg upgrade` preserves
them across updates.

### 10.3 Build chain

| Step | Where it runs |
|---|---|
| 1. Build the frontend (`pnpm build → frontend/dist/`) | GitHub Actions `package` workflow |
| 2. Cross-compile each daemon for the target Go arch | Same workflow, host Go toolchain (`CGO_ENABLED=0`) |
| 3. Fetch the OpenWRT SDK for the target | Same workflow |
| 4. Symlink `package/bubbleui` into the SDK and run `make package/bubbleui/compile` with `BUBBLEUI_SRC` + `BUBBLEUI_BIN` pointing at the pre-built artifacts | Same workflow |
| 5. Upload the resulting `.ipk` as a build artifact (later: as a GitHub release asset on tag pushes) | Same workflow |

The package's Makefile deliberately bypasses `golang-package.mk` —
since we ship CGO-free static binaries, we don't need OpenWRT's Go
toolchain coupling. CI builds binaries directly with the host Go;
the SDK build is just an .ipk-packaging step. This keeps CI tractable
across OpenWRT releases (23.05 / 24.10 / SNAPSHOT) without per-version
fixups.

### 10.4 Pre-built images

**Position: the long-term goal is no pre-built images.** The project boundary is "package on top of vanilla OpenWRT," not "OpenWRT distribution" (§13.4). Maintaining a per-device, per-version image matrix — release engineering, signing keys, OTA infra, vendor-specific factory-image variants — is the kind of work that turns a focused package into a distribution, and that is explicitly not what BubbleUI is.

**Where we are right now: testing-phase scaffold only.** During the pre-community phase of the project (no UI yet to show the open-source world, no community feedback on the install story), the package workflow does produce one pre-built `sysupgrade.bin`:

- **AXT1800 only** (`qualcommax/ipq60xx` / `glinet_gl-axt1800`), the Tier-1 reference device (§13.2).
- **One OpenWRT release at a time** — tracks whatever `OPENWRT_VERSION` `.github/workflows/package.yml` defaults to (currently 25.12.3). When upstream bumps, we bump; we don't keep a back-catalog.
- Built by the same `package` workflow that produces the `.apk`, using the matching OpenWRT Image Builder with the BubbleUI `.apk` dropped into its local feed so all transitive deps are baked into the rootfs.
- Ships alongside the `.apk` as the artifact `bubbleui-firmware-glinet_gl-axt1800-<version>` for the maintainer and early testers to try the product on real hardware without doing a full SDK build themselves.

This artifact exists because the audience (low-to-middling tech ability; see Goals) can't bootstrap a stock OpenWRT install plus `apk add bubbleui` themselves, and we don't yet have the community input to design the eventual install path. It is a deliberately narrow stopgap — one device, one OpenWRT release, no signing infrastructure, no OTA, no release channels.

**What this is not.** We do not ship per-device builds. We do not promise to add devices to the image matrix on request. We do not commit to a release cadence for the pre-built image. If a Tier-2 user wants their device to "just work" the same way, the answer is the same as for any other capable user on any other Tier-2 device: build the package from the SDK and `apk add` it (§10.3). Expanding the pre-built matrix is opposite to the goal; we will say no.

**What replaces it eventually.** Undecided, and deliberately so. The candidates we expect to weigh once there is a working UI to put in front of the community:

- A one-command Image Builder recipe the user runs locally (covers any vanilla-OpenWRT-supported device without a CI matrix on our side).
- A sysupgrade-from-running-OpenWRT path that doesn't require flashing at all.
- Community-curated per-vendor recipes, kept outside this repo.
- Something the community surfaces that we haven't thought of.

Picking among these is work that follows showing the UI to the community, not work that precedes it.

## 11. Open questions

1. **Credential storage.** *Resolved:* a small SQLite DB at `/etc/bubble/credentials.db` holding all credential types (YubiKey-self-wrapped `S` ciphertext, WebAuthn credential public keys + IDs, recovery code BLAKE2s hash). UCI is unsuitable for the binary blobs WebAuthn requires; SQLite is small enough to be unobtrusive on the AXT1800.
2. **Setup-mode network.** *Resolved:* `192.168.8.1` (the GL.iNet hardware default; minimizes collisions with hotel/home networks that almost universally use `192.168.0/1.x`). See §6.6.
3. **Firmware update flow.** Out of scope for *now*, not forever. We keep `sysupgrade` compatibility intact (don't write to flash regions it expects to manage, don't break the standard upgrade tarball format) so a managed upgrade path can land cleanly post-v1.0.
4. **Telemetry.** *Resolved:* none, ever. No counters, no error reporting, no opt-in. Crash diagnostics are surfaced in-product via a "Report issue" button that bundles redacted logs (system + daemon logs, sanitized firewall/network state, redacted config) into a downloadable file and pre-fills a GitHub issue template. The user reviews and submits manually. No callback URL, no automatic upload.
5. **VPN provider strategy** *(partially resolved)*.
   - **v1.0:** WireGuard-only, but as a *pool of saved configs* with active probing — user imports N `.conf` files once, the daemon TCP-connects to each endpoint at connect time and picks the lowest RTT. Per-row enable toggle, "stale" indicator when a config stops handshaking, automatic fail-over to next candidate on three-strike failure. This delivers the "Quick Connect" UX from the Proton/Mullvad apps without an API integration, and the prober/selector code is exactly what the v1.1 provider plugins will reuse.
   - **Post-v1.0 roadmap:** ProtonVPN account login (SRP auth + dynamic WG provisioning + live server list — see §11.5b). Cloudflare WARP fallback via `wgcf`-generated configs. Mullvad / iVPN as additional plugins. All of these become "config sources" feeding into the same pool + prober already shipping in v1.0.
   - **Plugin shape for `bubble-vpnd`:** the daemon grows a `provider` interface (`list_servers → connect(target) → disconnect → status → pick_fastest(filters)`) so each post-1.0 provider is additive, not a rewrite. The v1.0 WG-pool implementation is the reference plugin.

6. **MAC and hostname privacy** *(deferred — v1.x)*. The default OpenWRT hostname (`OpenWrt`) and a stable WAN MAC are a fingerprint that follows the user from network to network. §6.5 already pins stable-per-SSID as the WAN MAC baseline (a fresh MAC each time the user connects to a new upstream SSID). This adds three layered extensions:
   - **Time-based rotation** *(opt-in)*. Rotate all interface MACs — WAN-side STA, travel-SSID AP, LAN — on a user-configurable cadence. Pre-canned presets: 24h (the Apple iOS Private Wi-Fi Address default), 7d, 30d. Custom interval allowed. Rotation fires on a tick boundary, not mid-association — an active connection survives until the next reconnect. Stable-per-SSID remains the default; time-based stacks on top.
   - **OUI picker** *(opt-in)*. Replace locally-administered random MACs (first byte `0x02`/`0x06`/`0x0a`/`0x0e`, which some networks treat as suspicious) with a vendor OUI of the user's choice. Curated list bundled in firmware (Apple, Samsung, Intel, etc.); first three bytes fixed, last three randomized per rotation.
   - **Hostname privacy** *(default-on)*. The default hostname is *never* `OpenWrt`. Wizard picks a neutral default at setup, or one that pattern-matches the selected OUI (`iPhone` for an Apple OUI, `Galaxy` for Samsung, etc.). User can override with any string at any time. The DHCP client identifier and mDNS broadcasts share the hostname, so this single setting covers all the obvious leak points.

7. **Connectivity probe target for §6.8.** The state machine in §6.8 needs a signal for "the router itself is actually online" — distinct from "the OS captive-portal probe domains say we're online," since an AP we just associated to could be lying about those. Tradeoffs:
   - **Use one of the OS-standard probe domains** (Apple/Google/Microsoft/Mozilla). Convenient, well-tested, but adds the project to a big-tech request log every state-check tick — at odds with the threat model in §3.
   - **Self-host a probe URL** (`probe.bubbleui.dev` or similar). Privacy-clean from the user's side but means we operate infra and that infra's request log becomes privacy-sensitive to us-as-maintainers; also a single point of failure.
   - **Multi-probe quorum.** Hit 2-of-3 unrelated hosts (e.g. Mozilla + Quad9 + a self-hosted), succeed if any succeed, with cert pinning on each. Best privacy properties, more code.
   - **Decision for M3:** single-probe with cert pin to `https://detectportal.firefox.com/success.txt` as a deliberate placeholder. Mozilla has the least-bad privacy posture of the OS-probe operators, the success.txt response is trivially verifiable, and the pin foils mid-flight tampering. Revisit before v1.0 — quorum is the likely landing spot.

8. **HW-bound at-rest wrap via FIDO2 `hmac-secret`** *(post-v1.0)*. Earlier drafts of §5.5 used the router-attached YubiKey's HMAC-SHA1 oracle to derive a wrap key for the slot-2 secret stored on disk: physical theft of the router without the key yielded nothing usable. That construction is gone with the router-attached path (§5.1). The intended replacement is the FIDO2 `hmac-secret` extension on a registered WebAuthn credential — the user's authenticator (Touch ID, YubiKey 5+, etc.) derives a per-credential symmetric key from a server-stored salt, the daemon uses that to wrap whatever symmetric secret needs at-rest protection (cached WG keys, future session-rebind tokens), and the wrapped blob can only be unwrapped while the user re-authenticates with that authenticator. Work items: (a) verify `github.com/go-webauthn/webauthn` supports the `hmac-secret` extension parameter on both register and assert (it does as of v0.10.x, but we haven't wired it); (b) add a per-credential salt column to the credentials store; (c) gate the wrap flow on a fresh assertion so the wrap key never persists in RAM beyond a single login window; (d) decide what actually gets wrapped — there is nothing in v1.0 that strictly needs HW-bound at-rest protection (WG private keys are the most defensible candidate), so this remains an enabling design, not a forcing one.

9. **TOTP as an optional second factor on top of WebAuthn** *(under exploration; possibly v1.1)*. Today, the auth flow is single-factor: a successful WebAuthn assertion mints a session. The user has asked whether we can offer an opt-in "WebAuthn **and** TOTP" mode where both factors are required at every login. Sketched design:

   - **Provisioning.** Settings → Security → "Add TOTP as a second factor." Daemon generates a 160-bit random secret, surfaces it as both a QR (otpauth://) and a typed string. User enrolls in an authenticator app (Aegis, Bitwarden, Authy, etc.) on a device of their choice and confirms by typing a current code. Server validates the code, stores the secret, marks 2FA enabled. Per-user single TOTP enrollment — no multi-TOTP, no per-authenticator TOTP.
   - **Login.** After `FinishLoginWebAuthn` validates the assertion, if 2FA is enabled the daemon does NOT mint a session yet — it returns a "2fa_required" challenge with a short-lived (60s) handle. SPA prompts for the 6-digit code. `POST /auth/2fa/totp/verify` accepts `{handle, code}`, validates against the stored secret with the standard ±1 window (30s clock skew tolerance), and on success mints the session.
   - **Anti-replay.** Store the last accepted code's counter (`floor(time/period)`). Reject reuse within the validity window. Standard TOTP hygiene.
   - **Recovery.** Lose the WebAuthn authenticator and the TOTP authenticator both → recovery code path (§5.4) wipes the credential set AND the TOTP secret, returning to setup mode. Lose just the TOTP authenticator → "Re-enroll TOTP" flow gated on a fresh WebAuthn assertion plus a recovery-code burn (one-time use; a new recovery code is minted). Lose just the WebAuthn authenticator → existing register-new-credential flow already supports this; TOTP enrollment carries forward unchanged.
   - **Time correctness.** §6.6 already nails this — browser-supplied time at first boot, daemon refuses to fire TOTP at all until the clock is plausible (within `now - persisted_last_seen` of `now`, plus a sanity floor of "year ≥ 2024"). Stale-clock failures must surface to the user as "the router's clock is wrong, re-sync from your browser" — not as "TOTP rejected".
   - **Storage and the §11.8 dependency.** The TOTP shared secret is *symmetric* — anyone who can read `/etc/bubble/credentials.db` plus knows the time can produce valid codes. This is the same at-rest-secret problem §11.8 is meant to solve for the WebAuthn-side. Until §11.8 lands, on-disk theft of the router yields a TOTP secret that the attacker can use until the user rotates it. This is the chief reason TOTP is positioned as v1.1, not v1.0: it pairs naturally with §11.8 and shipping it without HW-bound wrap is a strict downgrade vs. WebAuthn-alone for the router-physically-stolen threat. If we ship before §11.8, the UI must clearly state "second factor adds defense against *remote* compromise of your authenticator; it does **not** add defense if the router itself is physically taken."
   - **Threat-model honest answer.** TOTP-as-2FA primarily defends against an attacker who has compromised the user's WebAuthn authenticator but does NOT have access to a *second* device storing the TOTP secret. The audience benefit is real if (and only if) the user stores TOTP on a device different from where their WebAuthn factor lives — phone's authenticator app while WebAuthn is the laptop's platform authenticator, or vice versa. If both factors live on the same phone (Authy + iCloud-Keychain platform passkey), 2FA collapses to 1FA at the device level. Wizard / Settings should explicitly nudge "use a different device for TOTP than for WebAuthn" — not enforce, since enforcement is brittle and the user might have only one device.
   - **Implementation cost.** `github.com/pquerna/otp` is the standard pure-Go TOTP library (`otp/totp`), small, well-maintained, no transitive deps. Net code add ≈150 LOC + tests + a small UI step. The expensive part is the UX of doing 2FA *well* for an audience that hasn't done it before (clear copy, the right friction at enrollment, sane error messages, the time-skew fallback path).
   - **Open question we'll resolve before greenlighting:** is the user's threat model genuinely better-served by TOTP-as-2FA than by **multi-WebAuthn-credential** (register both your laptop's platform authenticator *and* your phone's, requiring either to log in — adds "device variety" against single-device compromise without the symmetric-secret-on-router problem)? Multi-credential is already implemented today. If the user-as-product-author values "two distinct ceremonies at every login" more than "two distinct devices either of which works," TOTP wins; otherwise multi-credential is the cheaper, stronger answer. We discuss before committing.

## 12. Milestones

- **M0 — this doc.** Design freeze, repo scaffold lands.
- **M1 — frontend skeleton.** Svelte+Vite app with mock RPC, all screens stubbed, Nerd Font wired in.
- **M2 — auth.** `bubble-authd` shell PoC against a real YubiKey on a Linux box (not router yet). Recovery code path tested.
- **M3 — ubus wiring.** Run on a real OpenWRT device. Hotel WiFi (including the captive-portal sign-in flow per §6.5) + travel SSID screens functional.
- **M4 — VPN + DNS.** WireGuard kill switch, DoH default. WG runs as a *pool of saved configs* with TCP-connect probing and `Connect to fastest` as the default action; auto fail-over to the next candidate on handshake failure. End-to-end on hardware.
- **M5 — packaging.** `.ipk`, install docs, first tagged release (**v1.0**).
- **M6+ — provider plugins.** ProtonVPN account login (SRP + dynamic WG provisioning), Cloudflare WARP fallback via `wgcf`, additional providers as community asks. Each one is a new source feeding the same pool + prober shipped in M4.
- **M7 — privacy hardening.** Time-based MAC rotation, OUI picker, hostname privacy — see §11.6.

## 13. Hardware target

BubbleUI runs on **vanilla OpenWRT 23.05+** on any device that meets the
resource floor in §13.3. We don't ship per-device builds; one `.ipk` per
CPU architecture covers everything. Hardware diversity is handled by
OpenWRT's UCI/board.json layer (see §14), not by us.

Three tiers describe what "supported" means:

### 13.1 Support tiers

| Tier | What it covers | What we promise |
|---|---|---|
| **1 — Tested** | The reference device (GL.iNet GL-AXT1800), plus any device the maintainer regularly carries. Exercised in CI integration tests and personally bench-tested. | Bugs are bugs; the wizard is expected to work end-to-end. |
| **2 — Should work** | Any vanilla-OpenWRT-supported device that meets the §13.3 resource floor and ships in one of our cross-compile architecture targets. | Best-effort. The §14 UCI-driven hardware abstraction means it almost certainly works; bug reports welcome but not gating. |
| **3 — Out of scope** | Below the resource floor; needs hardware we don't abstract (cellular modems, custom RGB controllers); not in OpenWRT's Table of Hardware. | Not supported. The .ipk may install but behavior is undefined. |

### 13.2 Reference device — GL-AXT1800 (Slate AX)

The maintainer's bench device and the only Tier-1-tested target today.
Picked because it's the cleanest VPN-capable travel router in its
segment: vanilla OpenWRT support is mature (`qualcommax/ipq60xx`
target), the USB 3.0 port is well-suited for an always-attached
YubiKey, and the WiFi 6 dual-radio config supports simultaneous AP+STA
on different bands without contention.

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

Other devices the maintainer might add to Tier 1 over time: Beryl AX
(GL-MT3000), Marble (GL-MT6000), Brume 2 (GL-MT2500, no-WiFi VPN
gateway). Each addition is a CI matrix entry plus benchwork; no code
changes assumed.

### 13.3 Resource floor (Tier 2 minimum)

| | |
|---|---|
| Frontend bundle (HTML+JS+CSS+font) | < 400 KB target, ~85 KB realistic (current: 65 KB un-fonted) |
| Each Go daemon, statically-linked stripped | 8-15 MB (current: `bubble-authd` 11 MB linux/arm64) |
| Total BubbleUI install footprint | < 50 MB on flash (four Go daemons + frontend + configs) |
| BubbleUI RAM at idle (all daemons) | < 50 MB |
| **Device floor for Tier 2** | **128 MB flash, 256 MB RAM** |

The floor excludes the cheapest travel routers (16/32 MB ath79
boxes — Mango GL-MT300N etc.) where our stack simply doesn't fit. It
includes essentially every modern OpenWRT-supported device: the
Beryl/Slate/Marble/Brume/Spitz line from GL.iNet, x86 mini-PCs,
RPi-with-USB-Ethernet builds, NanoPi R6S etc.

The original draft assumed each daemon would land at 3-6 MB; in
practice `go-webauthn` pulls in TPM/COSE/CBOR machinery that brings
`bubble-authd` to ~11 MB statically-linked. Trading binary size for
"drop the file on the router and run, no shared-library hunt" is the
right deal at this hardware tier.

### 13.4 Firmware base — vanilla OpenWRT only

**Vanilla OpenWRT 23.05 or later. GL.iNet's stock firmware is explicitly out of scope and not supported.**

Reasons, not tradeoffs:

- GL.iNet's firmware is a heavily customized OpenWRT fork with uneven update cadence. Vanilla gets reliable security updates from upstream.
- We don't want to inherit GL.iNet's UI, their bundled apps, their telemetry, or their WAN-side cloud features.
- Sticking to vanilla is what makes Tier 2 meaningful: any vanilla-OpenWRT-supported device speaks our UCI/board.json language.

### 13.5 Cross-compile matrix

The CI build pipeline targets the architectures that cover the
overwhelming majority of modern OpenWRT-compatible devices in our
resource floor:

| Target | OpenWRT name | Covers |
|---|---|---|
| `linux/arm64` | `aarch64_cortex-a53` | ipq60xx (AXT1800), mt7986a (Marble, Beryl AX), most modern qualcommax/mediatek |
| `linux/arm` | `arm_cortex-a7_neon-vfpv4` | mt7621 (Slate Plus, older travel routers) |
| `linux/amd64` | `x86_64` | x86 mini-PCs, Protectli, generic OpenWRT-on-PC builds |

A fourth (`mips_24kc` for legacy mt7621 / ar71xx) is a build-on-request
add since those devices increasingly fail the resource floor anyway.

### 13.6 Radio plan

- **Travel SSID (AP):** 5 GHz default. Less congested in hotels, faster, supports more devices.
- **Hotel uplink (STA):** 2.4 GHz default. Better penetration, more universally available.
- User can swap in settings if a particular trip's hotel is 5 GHz only.

### 13.7 LED behavior

| State | LED |
|---|---|
| Setup mode | solid blue |
| Booting | white pulse |
| Tunnel up, secured | solid green |
| Captive-portal sign-in window open (§6.5) | slow yellow blink |
| Tunnel down, kill switch active | slow red blink |
| Hardware fault / YubiKey expected but missing | fast red blink |

The actual mapping from these abstract states to a particular device's
LED hardware is handled by §14's hardware abstraction — `bubble-hwd`
asks UCI which LED entries exist and what their colors are, then renders
the state via brightness + blink triggers.

## 14. Hardware abstraction strategy

BubbleUI's daemons ask **UCI / `/etc/board.json` first, sysfs second,
configured override third.** The intent is to get every Tier-2 device
working without per-device driver code on our side.

### 14.1 Why

Argon, Alpha, and the other LuCI themes "support every OpenWRT device"
because they don't actually do hardware abstraction — they sit on top
of LuCI, which sits on top of UCI, which sits on top of OpenWRT's
per-device DTS / board.json / kmod packaging. That's the whole trick.
We adopt the same pattern, with our own SPA + auth stack on top.

### 14.2 What our daemons consult

| Concern | Source of truth |
|---|---|
| LED entries (which sysfs path is the status LED, what color, what triggers exist) | `uci show system` (LED sections) → `/sys/class/leds/<sysfs>/...` for the actual write |
| Button mappings (which `/dev/input/event*` is "reset", which is the mode switch) | `uci show system` (button sections) + `/etc/rc.button/<name>` hotplug convention |
| Network interfaces (which iface is WAN, which is LAN bridge) | `uci show network` |
| Wireless radios (which `phy*` is 2.4 vs 5 GHz, max client count) | `uci show wireless` + `iw phy` |
| Firewall zones | `uci show firewall` |
| Device identity (model, board name, target architecture) | `ubus call system board` |

For each, our daemons write through `uci` for persistent changes and
through `ubus` for runtime queries — never poking sysfs/procfs paths
directly when an OpenWRT abstraction exists.

### 14.3 Fallback ladder

For each piece of hardware our daemons need to bind:

1. **UCI lookup** — does OpenWRT already declare this? If yes, use it.
2. **Runtime probe** — scan `/sys/class/leds`, `/dev/input/event*`,
   `iw dev`, etc. for what's actually present.
3. **Configured override** — `/etc/bubble/hardware.json` lets the user
   pin specific paths when neither of the above gets it right (e.g.,
   weird out-of-tree LED on a community device).

The override file is the escape hatch. Most Tier-2 devices never need
it; documented for the long-tail cases.

### 14.4 Quirks registry

A small Go package (`internal/quirks`) maps known board strings (from
`ubus call system board`) to known overrides. This is where
device-specific knowledge accumulates — e.g., "the AXT1800's 'wlan'
LED is actually the WAN-side activity light, not a status LED, so
prefer the system LED entry" or "the Marble has no usable status LED,
fall back to the GPIO behind the case."

PRs to extend the quirks registry are how new devices opt into Tier 2
"just works" status. No driver code required.

### 14.5 What this commits us to

- **Don't write our own hardware drivers** when OpenWRT already drives the hardware. We're an application, not a BSP.
- **Don't fork per-device variants** of any binary. One `.ipk` per architecture, hardware diversity at config-time.
- **Don't hide the UCI/ubus surface** from users who want more than we expose. We're a focused web UI, not a replacement OS. For niche tweaks a power user can install LuCI on demand (`apk add luci`) — an explicit, security-weakening opt-in (§2, §5.1), not something we ship by default.


