# BubbleUI — frontend

Svelte 5 + Vite + TypeScript SPA. The UI talks to OpenWRT's `ubus` over
JSON-RPC via `uhttpd` in production. In development it uses an in-memory
mock (`src/lib/mock.ts`) so you don't need a router on the bench.

## Quick start

```sh
pnpm install
pnpm fonts          # downloads CaskaydiaCove Nerd Font Mono (.ttf) into ./public/fonts
pnpm dev            # http://localhost:5173
```

The dev server will hot-reload as you change files. Login accepts any
non-empty password — the real YubiKey flow lands in M2.

## Scripts

| script        | what it does                                                |
|---------------|-------------------------------------------------------------|
| `pnpm dev`    | start Vite dev server with the mocked RPC transport         |
| `pnpm build`  | production build into `./dist`                              |
| `pnpm check`  | run `svelte-check` (types + a11y)                           |
| `pnpm fonts`  | fetch CaskaydiaCove Nerd Font Mono into `./public/fonts/`   |

## Fonts

We use **CaskaydiaCove Nerd Font Mono** for both UI text and icons. The font
binaries are not committed (see root `.gitignore`); run `pnpm fonts` to
fetch them. The script downloads from the
[ryanoasis/nerd-fonts](https://github.com/ryanoasis/nerd-fonts/releases)
release tagged in `scripts/fetch-fonts.mjs` and drops three weights
(Regular, SemiBold, Italic) into `public/fonts/`.

For M2 we'll add a subset+WOFF2 step so we ship < 60 KB instead of the
full ~4 MB TTFs.

To swap the font, change `--font-mono` in `src/app.css` and re-fetch
the corresponding family.

## Layout

```
src/
├── App.svelte                 shell, routing, header, nav
├── main.ts                    bootstrap
├── app.css                    base styles + @font-face
├── lib/
│   ├── icons.ts               Nerd Font glyph constants
│   ├── router.ts              tiny hash router
│   ├── rpc.ts                 ubus JSON-RPC client
│   ├── mock.ts                in-memory mock transport
│   └── session.svelte.ts      auth state (rune-based store)
└── routes/
    ├── Login.svelte
    ├── Dashboard.svelte       /
    ├── Wifi.svelte            /wifi    — hotel WiFi + captive portal
    ├── Vpn.svelte             /vpn     — WireGuard + kill switch
    ├── Ssid.svelte            /ssid    — travel SSID + isolation
    └── Dns.svelte             /dns     — DoH/DoT + enforcement
```

## Talking to a real router

When pointing at a real OpenWRT device:

1. Build with `VITE_USE_MOCK=false pnpm build`.
2. Serve `dist/` from uhttpd at `/`.
3. The app expects `/ubus` and `/auth` to be reachable on the same
   origin. The bundled `vite.config.ts` proxies these to `127.0.0.1:8080`
   during dev for testing against a router on the LAN.
