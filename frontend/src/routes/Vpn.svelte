<script lang="ts">
  import { onMount } from 'svelte';
  import * as api from '../lib/api';
  import type { VPNConfig, VPNStatus } from '../lib/api';
  import { ICON } from '../lib/icons';

  let configs = $state<VPNConfig[]>([]);
  let status = $state<VPNStatus | null>(null);
  let loading = $state(false);
  let probing = $state(false);
  let connecting = $state(false);
  let error = $state('');

  let importLabel = $state('');
  let importRaw = $state('');
  let importing = $state(false);

  async function refresh() {
    loading = true;
    const [list, st] = await Promise.all([api.vpnList(), api.vpnStatus()]);
    loading = false;
    if (list.ok) configs = list.data.configs ?? [];
    if (st.ok) status = st.data;
  }

  async function probe() {
    probing = true;
    error = '';
    const r = await api.vpnProbe();
    probing = false;
    if (!r.ok) {
      error = r.error.error;
      return;
    }
    configs = r.data.ranked ?? [];
  }

  async function connectFastest() {
    connecting = true;
    error = '';
    const r = await api.vpnConnectFastest();
    connecting = false;
    if (!r.ok) {
      error = r.error.error;
      return;
    }
    await refresh();
  }

  async function connectOne(id: number) {
    connecting = true;
    error = '';
    const r = await api.vpnConnectByID(id);
    connecting = false;
    if (!r.ok) {
      error = r.error.error;
      return;
    }
    await refresh();
  }

  async function disconnect() {
    connecting = true;
    error = '';
    await api.vpnDisconnect();
    connecting = false;
    await refresh();
  }

  async function toggleEnabled(c: VPNConfig) {
    const r = await api.vpnSetEnabled(c.id, !c.enabled);
    if (!r.ok) {
      error = r.error.error;
      return;
    }
    c.enabled = !c.enabled;
  }

  async function destroy(id: number) {
    if (!confirm('Remove this config from the pool?')) return;
    const r = await api.vpnDelete(id);
    if (!r.ok) {
      error = r.error.error;
      return;
    }
    await refresh();
  }

  async function importConfig(e: Event) {
    e.preventDefault();
    if (!importRaw.trim()) {
      error = 'paste a WireGuard config first';
      return;
    }
    importing = true;
    error = '';
    const r = await api.vpnImport(importLabel, importRaw);
    importing = false;
    if (!r.ok) {
      error = r.error.error;
      return;
    }
    importLabel = '';
    importRaw = '';
    await refresh();
  }

  // Drag-drop a .conf file into the import textarea.
  async function onDrop(e: DragEvent) {
    e.preventDefault();
    const f = e.dataTransfer?.files?.[0];
    if (!f) return;
    importLabel = f.name.replace(/\.conf$/i, '');
    importRaw = await f.text();
  }

  function fmtAge(ts?: number): string {
    if (!ts) return 'never';
    const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  function probeBadge(c: VPNConfig): { text: string; cls: string } {
    if (c.probe_err || c.last_probe_err) {
      return { text: 'unreachable', cls: 'err' };
    }
    if (typeof c.probe_rtt_ms === 'number') {
      return { text: c.probe_rtt_ms + ' ms', cls: 'ok' };
    }
    if (typeof c.last_probe_rtt_ms === 'number') {
      return { text: c.last_probe_rtt_ms + ' ms', cls: 'ok' };
    }
    return { text: 'untested', cls: 'dim' };
  }

  onMount(refresh);
</script>

<section>
  <header class="head">
    <h2>WireGuard pool</h2>
    <div class="actions">
      <button onclick={probe} disabled={probing || configs.length === 0}>
        <span class="icon" class:spin={probing}>{ICON.refresh}</span>
        {probing ? 'probing…' : 'probe all'}
      </button>
      {#if status?.active_id}
        <button onclick={disconnect} disabled={connecting}>
          <span class="icon">{ICON.unlock}</span>
          disconnect
        </button>
      {:else}
        <button onclick={connectFastest} disabled={connecting || configs.length === 0}>
          <span class="icon">{ICON.bolt}</span>
          {connecting ? 'connecting…' : 'connect to fastest'}
        </button>
      {/if}
    </div>
  </header>

  {#if error}
    <p class="err"><span class="icon">{ICON.err}</span> {error}</p>
  {/if}

  {#if status?.active_id}
    <div class="active">
      <span class="icon">{ICON.shield}</span>
      <strong>Connected</strong>
      <span class="active-label">{status.label} ({status.endpoint})</span>
    </div>
  {/if}

  {#if configs.length === 0 && !loading}
    <div class="empty">
      <p>The pool is empty. Drop a WireGuard <code>.conf</code> file below to get started.</p>
    </div>
  {/if}

  <ul class="list">
    {#each configs as c (c.id)}
      <li class:active={status?.active_id === c.id} class:disabled={!c.enabled}>
        <label class="enable">
          <input
            type="checkbox"
            checked={c.enabled}
            onchange={() => toggleEnabled(c)}
            title="enable in pool"
          />
        </label>
        <div class="meta">
          <div class="line1">
            <strong>{c.label}</strong>
            <span class="endpoint">{c.endpoint}</span>
          </div>
          <div class="line2">
            <span class="pill {probeBadge(c).cls}">{probeBadge(c).text}</span>
            {#if c.last_probe_at}
              <span class="dim">probed {fmtAge(c.last_probe_at)}</span>
            {/if}
            {#if c.last_handshake_at}
              <span class="dim">handshake {fmtAge(c.last_handshake_at)}</span>
            {/if}
            {#if c.last_probe_err}
              <span class="err-text" title={c.last_probe_err}>
                {c.last_probe_err.length > 60 ? c.last_probe_err.slice(0, 60) + '…' : c.last_probe_err}
              </span>
            {/if}
          </div>
        </div>
        <div class="row-actions">
          {#if status?.active_id !== c.id}
            <button onclick={() => connectOne(c.id)} disabled={!c.enabled || connecting}>
              connect
            </button>
          {/if}
          <button class="danger" onclick={() => destroy(c.id)} title="remove">
            <span class="icon">{ICON.err}</span>
          </button>
        </div>
      </li>
    {/each}
  </ul>

  <details class="import" open={configs.length === 0}>
    <summary>Import WireGuard config</summary>
    <form
      onsubmit={importConfig}
      ondragover={(e) => e.preventDefault()}
      ondrop={onDrop}
    >
      <label>
        <span>Label (optional)</span>
        <input bind:value={importLabel} placeholder="e.g. ch-zurich-12" />
      </label>
      <label>
        <span>Paste a .conf or drop a file</span>
        <textarea
          rows="10"
          bind:value={importRaw}
          placeholder={'[Interface]\nPrivateKey = …\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = …\nEndpoint = vpn.example:51820\nAllowedIPs = 0.0.0.0/0'}
        ></textarea>
      </label>
      <button type="submit" disabled={importing || !importRaw.trim()}>
        {importing ? 'importing…' : 'add to pool'}
      </button>
    </form>
  </details>
</section>

<style>
  h2 { margin: 0; font-size: 16px; font-weight: 600; }
  .head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; gap: 8px; }
  .actions { display: flex; gap: 8px; }

  .err { color: var(--accent-err); margin: 0 0 8px 0; font-size: 13px; }
  .err-text { color: var(--accent-err); font-size: 12px; }

  .active {
    display: flex;
    align-items: center;
    gap: 10px;
    background: color-mix(in srgb, var(--accent-ok) 12%, transparent);
    border: 1px solid var(--accent-ok);
    border-radius: var(--radius);
    padding: 10px 12px;
    margin-bottom: 12px;
    font-size: 14px;
  }
  .active strong { color: var(--accent-ok); }
  .active-label { color: var(--fg-dim); font-size: 13px; }

  .empty {
    background: var(--bg-elev);
    border: 1px dashed var(--border);
    border-radius: var(--radius);
    padding: 16px;
    color: var(--fg-dim);
    font-size: 13px;
    text-align: center;
    margin-bottom: 12px;
  }

  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 4px;
  }
  .list li {
    display: grid;
    grid-template-columns: auto 1fr auto;
    gap: 12px;
    padding: 10px 12px;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    align-items: center;
  }
  .list li.active { border-color: var(--accent-ok); }
  .list li.disabled { opacity: 0.55; }

  .enable input { width: auto; }

  .meta { display: grid; gap: 4px; min-width: 0; }
  .line1 {
    display: flex;
    gap: 10px;
    align-items: baseline;
    overflow: hidden;
  }
  .endpoint { color: var(--fg-dim); font-size: 12px; }
  .line2 { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; font-size: 12px; }
  .dim { color: var(--fg-faint); }

  .pill.dim { color: var(--fg-faint); border-color: var(--border); }

  .row-actions { display: flex; gap: 6px; }
  .row-actions button.danger {
    color: var(--accent-err);
    padding: 6px 8px;
  }

  details.import { margin-top: 16px; background: var(--bg-elev); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px; }
  summary { cursor: pointer; color: var(--fg-dim); }
  details form { margin-top: 12px; display: grid; gap: 12px; }
  details label { display: grid; gap: 6px; }
  details label > span { color: var(--fg-dim); font-size: 12px; }
  details textarea { font-family: var(--font-mono); font-size: 12px; resize: vertical; }

  .spin { display: inline-block; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
