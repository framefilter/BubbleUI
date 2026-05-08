<script lang="ts">
  import { onMount } from 'svelte';
  import { rpc } from '../lib/rpc';
  import { ICON } from '../lib/icons';

  interface WgStatus { up: boolean; peer: string | null; handshake_age: number | null }

  let status = $state<WgStatus | null>(null);
  let busy = $state(false);
  let killSwitch = $state(true);
  let configText = $state('');

  async function refresh() {
    const r = await rpc.call<WgStatus>('wireguard', 'status');
    if (r.ok) status = r.data;
  }

  async function toggle() {
    busy = true;
    if (status?.up) {
      await rpc.call('wireguard', 'down');
    } else {
      await rpc.call('wireguard', 'up', { peer: 'demo.example' });
    }
    await refresh();
    busy = false;
  }

  onMount(refresh);
</script>

<section>
  <h2>VPN</h2>

  <div class="card">
    <div class="row">
      <span class="icon">{ICON.shield}</span>
      <strong>WireGuard</strong>
      {#if status?.up}
        <span class="pill ok">connected</span>
      {:else}
        <span class="pill err">disconnected</span>
      {/if}
    </div>
    <small>
      {#if status?.up}
        Peer: {status.peer} · last handshake {status.handshake_age}s ago
      {:else}
        Tunnel is down. While the kill switch is on, LAN traffic is blocked.
      {/if}
    </small>
    <button onclick={toggle} disabled={busy}>
      {status?.up ? 'disconnect' : 'connect'}
    </button>
  </div>

  <label class="toggle">
    <input type="checkbox" bind:checked={killSwitch} />
    <span>
      <span class="icon">{killSwitch ? ICON.lock : ICON.unlock}</span>
      Kill switch
      <small>Drop LAN→WAN traffic when the tunnel is down. Recommended.</small>
    </span>
  </label>

  <details>
    <summary>Import WireGuard config</summary>
    <textarea
      rows="8"
      placeholder={'[Interface]\nPrivateKey = …\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = …\nEndpoint = vpn.example:51820\nAllowedIPs = 0.0.0.0/0'}
      bind:value={configText}
    ></textarea>
    <button disabled={!configText.trim()}>Import</button>
  </details>
</section>

<style>
  h2 { margin: 0 0 12px 0; font-size: 16px; font-weight: 600; }
  .card {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px;
    display: grid;
    gap: 8px;
    margin-bottom: 12px;
  }
  .row { display: flex; align-items: center; gap: 8px; }
  .row > strong { flex: 1; }
  small { color: var(--fg-dim); font-size: 12px; }

  .toggle {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 12px;
    align-items: start;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px;
    margin-bottom: 12px;
    cursor: pointer;
  }
  .toggle input { width: auto; margin-top: 4px; }
  .toggle small { display: block; margin-top: 2px; }

  details {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px;
  }
  summary { cursor: pointer; color: var(--fg-dim); }
  textarea {
    margin-top: 8px;
    font-family: var(--font-mono);
    font-size: 12px;
    resize: vertical;
  }
</style>
