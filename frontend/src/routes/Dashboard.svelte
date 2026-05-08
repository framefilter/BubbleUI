<script lang="ts">
  import { onMount } from 'svelte';
  import { rpc } from '../lib/rpc';
  import { ICON } from '../lib/icons';

  interface Board { model: string; release: { version: string } }
  interface SysInfo { uptime: number; load: number[]; memory: { total: number; free: number } }
  interface WgStatus { up: boolean; peer: string | null; handshake_age: number | null }
  interface DnsStatus { provider: string; mode: 'doh' | 'dot'; enforced: boolean }

  let board = $state<Board | null>(null);
  let info = $state<SysInfo | null>(null);
  let wg = $state<WgStatus | null>(null);
  let dns = $state<DnsStatus | null>(null);

  onMount(async () => {
    const [b, i, w, d] = await Promise.all([
      rpc.call<Board>('system', 'board'),
      rpc.call<SysInfo>('system', 'info'),
      rpc.call<WgStatus>('wireguard', 'status'),
      rpc.call<DnsStatus>('dns', 'status'),
    ]);
    if (b.ok) board = b.data;
    if (i.ok) info = i.data;
    if (w.ok) wg = w.data;
    if (d.ok) dns = d.data;
  });

  function fmtUptime(s: number): string {
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    return `${d}d ${h}h ${m}m`;
  }
</script>

<section>
  <h2>Status</h2>

  <div class="grid">
    <div class="card">
      <div class="row">
        <span class="icon">{ICON.shield}</span>
        <span>Tunnel</span>
        {#if wg?.up}
          <span class="pill ok">up</span>
        {:else}
          <span class="pill err">down</span>
        {/if}
      </div>
      <small>{wg?.peer ?? 'no peer configured'}</small>
    </div>

    <div class="card">
      <div class="row">
        <span class="icon">{ICON.globe}</span>
        <span>DNS</span>
        {#if dns?.enforced}
          <span class="pill ok">enforced</span>
        {:else}
          <span class="pill warn">leaky</span>
        {/if}
      </div>
      <small>{dns?.provider ?? '—'} via {dns?.mode ?? '—'}</small>
    </div>

    <div class="card">
      <div class="row">
        <span class="icon">{ICON.router}</span>
        <span>Device</span>
      </div>
      <small>{board?.model ?? '…'} ({board?.release.version ?? '—'})</small>
    </div>

    <div class="card">
      <div class="row">
        <span class="icon">{ICON.bolt}</span>
        <span>Uptime</span>
      </div>
      <small>{info ? fmtUptime(info.uptime) : '…'}</small>
    </div>
  </div>
</section>

<style>
  h2 { margin: 0 0 12px 0; font-size: 16px; font-weight: 600; }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 8px;
  }
  .card {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px;
    display: grid;
    gap: 4px;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .row > span:nth-child(2) { flex: 1; }
  small { color: var(--fg-dim); font-size: 12px; }
</style>
