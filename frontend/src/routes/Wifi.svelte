<script lang="ts">
  import { onMount } from 'svelte';
  import { rpc } from '../lib/rpc';
  import { net as netStore, refreshCaptive, refreshSignin, openSignin } from '../lib/netStore.svelte';
  import * as api from '../lib/api';
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
  let captiveProbing = $state(false);
  let opening = $state(false);
  let signinError = $state('');

  // Strict-mode toggle from §6.5. Lives here for now; if/when a Settings
  // page lands it migrates there.
  let strict = $state(false);

  const ns = netStore();

  async function scan() {
    loading = true;
    const r = await rpc.call<{ results: ScanResult[] }>('iwinfo', 'scan');
    loading = false;
    if (r.ok) nets = r.data.results;
  }

  async function probeCaptive() {
    captiveProbing = true;
    signinError = '';
    await refreshCaptive();
    captiveProbing = false;
  }

  async function openWindow() {
    if (!ns.captive?.captive || (ns.captive.portal_ips ?? []).length === 0) {
      signinError = 'no portal IPs detected; rerun the captive probe';
      return;
    }
    opening = true;
    signinError = '';
    const r = await openSignin(ns.captive.portal_ips ?? [], 600);
    opening = false;
    if (!r.ok) signinError = r.error.error;
  }

  async function toggleStrict() {
    strict = !strict;
    const r = await api.netSigninStrict(strict);
    if (!r.ok) {
      signinError = r.error.error;
      strict = !strict; // revert
      return;
    }
    await refreshSignin();
  }

  async function connect(n: ScanResult) {
    connecting = n.ssid;
    const r = await rpc.call<{ connected: boolean }>('wireless', 'connect', {
      ssid: n.ssid,
      encryption: n.encryption,
    });
    connecting = null;
    if (r.ok && r.data.connected) {
      connected = n.ssid;
      // After associating, immediately probe for a captive portal.
      void probeCaptive();
    }
  }

  function bars(signal: number): string {
    if (signal > -55) return '████';
    if (signal > -65) return '███ ';
    if (signal > -75) return '██  ';
    return '█   ';
  }

  onMount(() => {
    void scan();
    void probeCaptive();
    void refreshSignin();
    if (ns.signin) strict = ns.signin.strict_mode;
  });
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
        <button onclick={probeCaptive} disabled={captiveProbing} class="reprobe">
          <span class="icon" class:spin={captiveProbing}>{ICON.refresh}</span>
          recheck
        </button>
      </div>
    </div>
  {/if}

  {#if ns.captive?.captive && ns.signin?.state !== 'open'}
    <div class="card captive">
      <div class="row">
        <span class="icon">{ICON.warn}</span>
        <strong>Hotel WiFi requires sign-in</strong>
      </div>
      <p class="hint">
        A captive portal is intercepting traffic. Detected at
        <code>{(ns.captive.portal_ips ?? []).join(', ') || 'unknown IP'}</code>.
      </p>
      <p class="detail">
        Opening the sign-in window adds a tightly-scoped firewall hole:
        LAN→WAN to those IPs only, on TCP 80/443, for 10 minutes. The
        kill switch stays in place for everything else.
      </p>
      <div class="actions">
        <button onclick={openWindow} disabled={opening || ns.signin?.strict_mode}>
          {opening ? 'opening…' : 'Open sign-in window (10 min)'}
        </button>
        {#if ns.signin?.strict_mode}
          <span class="dim">(disabled by strict mode)</span>
        {/if}
      </div>
      {#if signinError}
        <p class="err"><span class="icon">{ICON.err}</span> {signinError}</p>
      {/if}
    </div>
  {:else if ns.captive && !ns.captive.captive}
    <div class="card clean">
      <span class="icon">{ICON.ok}</span>
      Internet looks fine — no captive portal detected.
    </div>
  {/if}

  <label class="toggle strict">
    <input type="checkbox" checked={ns.signin?.strict_mode ?? false} onchange={toggleStrict} />
    <span>
      <strong>Strict mode</strong>
      <small>
        Disable the captive-portal sign-in window entirely. With this on,
        captive portals must be cleared via a separate dedicated SSID;
        the kill switch is never relaxed. Recommended for high-threat trips.
      </small>
    </span>
  </label>

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
  .card.captive {
    background: var(--bg-elev);
    border: 1px solid var(--accent-warn);
    border-radius: var(--radius);
    padding: 12px;
    margin-bottom: 12px;
    display: grid;
    gap: 8px;
  }
  .card.captive .icon { color: var(--accent-warn); }
  .card.clean {
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--bg-elev);
    border: 1px solid var(--accent-ok);
    border-radius: var(--radius);
    padding: 8px 12px;
    margin-bottom: 12px;
    color: var(--accent-ok);
    font-size: 13px;
  }
  .row { display: flex; align-items: center; gap: 8px; }
  .row > strong { flex: 1; }
  .hint { color: var(--fg-dim); font-size: 13px; margin: 0; line-height: 1.5; }
  .detail { color: var(--fg-faint); font-size: 12px; margin: 0; line-height: 1.5; }
  .err { color: var(--accent-err); font-size: 13px; margin: 0; }
  .reprobe { background: transparent; border: 1px solid var(--border); padding: 4px 8px; font-size: 12px; }
  .actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .dim { color: var(--fg-dim); font-size: 12px; }

  .toggle.strict {
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
  .toggle.strict input { width: auto; margin-top: 4px; }
  .toggle.strict small { display: block; color: var(--fg-dim); margin-top: 2px; line-height: 1.5; }
  code { background: var(--bg); padding: 1px 4px; border-radius: 3px; }
  .spin { display: inline-block; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
