<script lang="ts">
  import { onMount } from 'svelte';
  import { currentPath, navigate, onChange } from './lib/router';
  import { session, logout, refresh } from './lib/session.svelte';
  import * as api from './lib/api';
  import { ICON } from './lib/icons';

  import Login from './routes/Login.svelte';
  import SetupNeeded from './routes/SetupNeeded.svelte';
  import Dashboard from './routes/Dashboard.svelte';
  import Wifi from './routes/Wifi.svelte';
  import Vpn from './routes/Vpn.svelte';
  import Ssid from './routes/Ssid.svelte';
  import Dns from './routes/Dns.svelte';

  let path = $state(currentPath());

  // Boot sequence:
  //   1. POST our wall-clock to /api/time/sync so the router has correct
  //      time before any TLS-dependent operation (DESIGN.md §6.6).
  //   2. Fetch /auth/session/whoami to populate session state.
  //   3. Subscribe to hash-route changes.
  onMount(() => {
    void api.timeSync(Date.now());
    void refresh();
    return onChange((p) => (path = p));
  });

  const s = session();

  const nav = [
    { path: '/',     label: 'Status',  icon: ICON.router },
    { path: '/wifi', label: 'WiFi',    icon: ICON.wifi },
    { path: '/vpn',  label: 'VPN',     icon: ICON.shield },
    { path: '/ssid', label: 'Travel',  icon: ICON.bolt },
    { path: '/dns',  label: 'DNS',     icon: ICON.globe },
  ];

  function go(e: MouseEvent, p: string) {
    e.preventDefault();
    navigate(p);
  }
</script>

{#if s.authenticated === undefined}
  <div class="boot"><span class="icon spin">{ICON.refresh}</span> connecting…</div>
{:else if s.setupNeeded}
  <SetupNeeded />
{:else if !s.authenticated}
  <Login />
{:else}
  <div class="shell">
    <header>
      <div class="brand"><span class="icon">{ICON.router}</span> BubbleUI</div>
      <div class="status">
        <span class="pill ok"><span class="icon">{ICON.key}</span> session #{s.credentialId}</span>
        <button onclick={logout} title="log out">{ICON.unlock}</button>
      </div>
    </header>

    <nav>
      {#each nav as item}
        <a
          href={'#' + item.path}
          class:active={path === item.path}
          onclick={(e) => go(e, item.path)}
        >
          <span class="icon">{item.icon}</span>
          <span>{item.label}</span>
        </a>
      {/each}
    </nav>

    <main>
      {#if path === '/'}
        <Dashboard />
      {:else if path === '/wifi'}
        <Wifi />
      {:else if path === '/vpn'}
        <Vpn />
      {:else if path === '/ssid'}
        <Ssid />
      {:else if path === '/dns'}
        <Dns />
      {:else}
        <p>Not found. <a href="#/" onclick={(e) => go(e, '/')}>Back to status</a></p>
      {/if}
    </main>
  </div>
{/if}

<style>
  .boot {
    min-height: 100vh;
    display: grid;
    place-items: center;
    color: var(--fg-dim);
    font-size: 14px;
    gap: 8px;
  }
  .spin { display: inline-block; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  .shell {
    max-width: 720px;
    margin: 0 auto;
    padding: 16px;
    display: grid;
    gap: 16px;
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
  }

  .brand {
    font-weight: 600;
    font-size: 16px;
  }

  .status {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  nav {
    display: flex;
    gap: 4px;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
  }

  nav a {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--fg-dim);
    white-space: nowrap;
  }
  nav a:hover { color: var(--fg); }
  nav a.active {
    color: var(--fg);
    border-color: var(--accent-ok);
    background: color-mix(in srgb, var(--accent-ok) 10%, transparent);
  }

  main { padding-top: 4px; }
</style>
