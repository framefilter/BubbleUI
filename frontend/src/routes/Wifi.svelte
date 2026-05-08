<script lang="ts">
  import { onMount } from 'svelte';
  import { rpc } from '../lib/rpc';
  import { ICON } from '../lib/icons';

  interface ScanResult {
    ssid: string;
    signal: number;
    encryption: string;
    bssid: string;
  }

  let nets = $state<ScanResult[]>([]);
  let loading = $state(false);
  let connecting = $state<string | null>(null);
  let connected = $state<string | null>(null);
  let captiveOpen = $state(false);

  async function scan() {
    loading = true;
    const r = await rpc.call<{ results: ScanResult[] }>('iwinfo', 'scan');
    loading = false;
    if (r.ok) nets = r.data.results;
  }

  async function connect(net: ScanResult) {
    connecting = net.ssid;
    const r = await rpc.call<{ connected: boolean }>('wireless', 'connect', {
      ssid: net.ssid,
      encryption: net.encryption,
    });
    connecting = null;
    if (r.ok && r.data.connected) {
      connected = net.ssid;
      // Mock: any open network is "probably captive."
      captiveOpen = net.encryption === 'open';
    }
  }

  function bars(signal: number): string {
    if (signal > -55) return '████';
    if (signal > -65) return '███ ';
    if (signal > -75) return '██  ';
    return '█   ';
  }

  onMount(scan);
</script>

<section>
  <header class="head">
    <h2>Hotel WiFi</h2>
    <button onclick={scan} disabled={loading}>
      <span class="icon" class:spin={loading}>{ICON.refresh}</span>
      {loading ? 'scanning' : 'rescan'}
    </button>
  </header>

  {#if connected}
    <div class="card connected">
      <div class="row">
        <span class="icon">{ICON.ok}</span>
        <strong>Connected to {connected}</strong>
      </div>
      {#if captiveOpen}
        <p class="captive">
          <span class="icon">{ICON.warn}</span>
          Captive portal likely. Open the hotel login page to authenticate.
        </p>
        <button>Open hotel login</button>
      {/if}
    </div>
  {/if}

  <ul class="list">
    {#each nets as net (net.bssid)}
      <li>
        <span class="bars" aria-hidden="true">{bars(net.signal)}</span>
        <span class="ssid">{net.ssid}</span>
        <span class="enc">
          <span class="icon">{net.encryption === 'open' ? ICON.unlock : ICON.lock}</span>
          {net.encryption}
        </span>
        <button
          onclick={() => connect(net)}
          disabled={connecting !== null}
        >
          {connecting === net.ssid ? 'connecting…' : 'connect'}
        </button>
      </li>
    {/each}
  </ul>
</section>

<style>
  .head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
  }
  h2 { margin: 0; font-size: 16px; font-weight: 600; }

  .list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: grid;
    gap: 4px;
  }
  .list li {
    display: grid;
    grid-template-columns: auto 1fr auto auto;
    align-items: center;
    gap: 12px;
    padding: 10px 12px;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }
  .bars { font-family: var(--font-mono); color: var(--accent-ok); letter-spacing: -1px; }
  .enc  { color: var(--fg-dim); font-size: 12px; }
  .ssid { font-weight: 500; }

  .card.connected {
    background: var(--bg-elev);
    border: 1px solid var(--accent-ok);
    border-radius: var(--radius);
    padding: 12px;
    margin-bottom: 12px;
    display: grid;
    gap: 8px;
  }
  .row { display: flex; align-items: center; gap: 8px; }
  .captive { color: var(--accent-warn); margin: 0; font-size: 13px; }
  .spin { display: inline-block; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
