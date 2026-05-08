<script lang="ts">
  import { onMount } from 'svelte';
  import { currentPath, navigate, onChange } from './lib/router';
  import { session, logout } from './lib/session.svelte';
  import { ICON } from './lib/icons';

  import Login from './routes/Login.svelte';
  import Dashboard from './routes/Dashboard.svelte';
  import Wifi from './routes/Wifi.svelte';
  import Vpn from './routes/Vpn.svelte';
  import Ssid from './routes/Ssid.svelte';
  import Dns from './routes/Dns.svelte';

  let path = $state(currentPath());
  onMount(() => onChange((p) => (path = p)));

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

{#if !s.authenticated}
  <Login />
{:else}
  <div class="shell">
    <header>
      <div class="brand"><span class="icon">{ICON.router}</span> BubbleUI</div>
      <div class="status">
        {#if s.hasKey}
          <span class="pill ok"><span class="icon">{ICON.key}</span> key present</span>
        {:else}
          <span class="pill err"><span class="icon">{ICON.key}</span> no key</span>
        {/if}
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
