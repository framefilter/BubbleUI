# BubbleUI

A simple, security-conscious travel UI for OpenWRT.

> Pre-alpha. Design freeze in progress — see [`DESIGN.md`](./DESIGN.md).

## What it is

BubbleUI is a focused, opinionated web UI for travel routers running vanilla
OpenWRT. It exposes the four things you actually need on the road — hotel
WiFi, a VPN with a kill switch, a per-trip SSID with client isolation, and
encrypted DNS — and auto-configures sensible, locked-down defaults for
everything else.

Admin UI access is gated by a USB-attached hardware key (YubiKey,
HMAC-SHA1 challenge-response) plugged into the router itself, with an
optional WebAuthn second factor on the client. A printed recovery code
covers a lost key.

## Status

| Milestone | State |
|---|---|
| M0 — Design freeze | in progress |
| M1 — Frontend skeleton | not started |
| M2 — Auth (YubiKey + recovery) | not started |
| M3 — ubus wiring on real hardware | not started |
| M4 — VPN + DNS | not started |
| M5 — Packaging (`.ipk`) | not started |

## Read next

- [`DESIGN.md`](./DESIGN.md) — architecture, threat model, auth flow, repo layout.
