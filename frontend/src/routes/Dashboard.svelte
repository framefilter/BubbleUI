<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import * as api from '../lib/api';
  import type { VPNStatus, SigninStatus, LEDState, Whoami } from '../lib/api';
  import { net as netStore } from '../lib/netStore.svelte';
  import { ICON } from '../lib/icons';

  // Aggregates state from all four daemons:
  //   bubble-authd   /auth/session/whoami        — credential ID + expiry
  //   bubble-vpnd    /vpn/status, /vpn/configs   — tunnel + pool size
  //   bubble-netd    (via netStore poll)         — sign-in + captive
  //   bubble-hwd     /hw/led                     — composed LED state
  let vpn = $state<VPNStatus | null>(null);
  let poolSize = $state<number>(0);
  let led = $state<LEDState>('unknown');
  let who = $state<Whoami | null>(null);

  let loadedAt = $state<number>(0);
  let intervalId: ReturnType<typeof setInterval> | null = null;

  const ns = netStore();

  async function refresh() {
    const [vpnStatus, vpnList, ledRes, whoRes] = await Promise.all([
      api.vpnStatus(),
      api.vpnList(),
      api.hwLEDGet(),
      api.whoami(),
    ]);
    if (vpnStatus.ok) vpn = vpnStatus.data;
    if (vpnList.ok) poolSize = vpnList.data.configs?.length ?? 0;
    if (ledRes.ok) led = ledRes.data.state;
    if (whoRes.ok) who = whoRes.data;
    loadedAt = Date.now();
  }

  onMount(() => {
    void refresh();
    intervalId = setInterval(refresh, 5000);
  });

  onDestroy(() => {
    if (intervalId !== null) clearInterval(intervalId);
  });

  function tunnelPill(): { text: string; cls: string } {
    if (!vpn) return { text: '…', cls: 'dim' };
    if (vpn.active_id) return { text: 'connected', cls: 'ok' };
    // No active tunnel is the correct steady state when the user
    // hasn't asked to connect yet — that's not an error condition,
    // it's just the kill switch doing its job. Reserve red for
    // states that actually need the user's attention.
    if (poolSize === 0) return { text: 'no configs', cls: 'dim' };
    return { text: 'disconnected', cls: 'warn' };
  }

  function signinPill(s: SigninStatus | null): { text: string; cls: string } {
    if (!s) return { text: '…', cls: 'dim' };
    if (s.state === 'open') return { text: 'sign-in open', cls: 'warn' };
    if (s.strict_mode) return { text: 'strict', cls: 'ok' };
    return { text: 'kill switch', cls: 'ok' };
  }

  function captivePill() {
    if (!ns.captive) return { text: '…', cls: 'dim' };
    if (ns.captive.captive) return { text: 'portal detected', cls: 'warn' };
    return { text: 'clear', cls: 'ok' };
  }

  function ledColor(s: LEDState): string {
    switch (s) {
      case 'secured':
        return 'var(--accent-ok)';
      case 'signin_open':
      case 'setup':
        return 'var(--accent-warn)';
      case 'killswitch_up':
      case 'no_key':
      case 'fault':
        return 'var(--accent-err)';
      case 'booting':
        return 'var(--fg-dim)';
      default:
        return 'var(--fg-faint)';
    }
  }

  function fmtExpiry(ts: number): string {
    const sec = Math.max(0, Math.floor(ts - Date.now() / 1000));
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (h > 24) return Math.floor(h / 24) + 'd ' + (h % 24) + 'h';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm';
  }

  function fmtAge(ms: number): string {
    if (ms === 0) return '—';
    const sec = Math.max(0, Math.floor((Date.now() - ms) / 1000));
    if (sec < 60) return sec + 's ago';
    return Math.floor(sec / 60) + 'm ago';
  }
</script>

<section>
  <header>
    <h2>Status</h2>
    <small class="loaded">refreshed {fmtAge(loadedAt)}</small>
  </header>

  <div class="grid">
    <div class="card">
      <div class="row">
        <span class="led" style="background: {ledColor(led)}"></span>
        <span>Router state</span>
        <span class="pill dim mono">{led}</span>
      </div>
      <small>composed from bubble-vpnd + bubble-netd by bubble-hwd</small>
    </div>

    <div class="card">
      <div class="row">
        <span class="icon">{ICON.shield}</span>
        <span>Tunnel</span>
        <span class="pill {tunnelPill().cls}">{tunnelPill().text}</span>
      </div>
      <small>
        {#if vpn?.active_id}
          {vpn.label} ({vpn.endpoint})
        {:else if poolSize === 0}
          no configs yet — import one on the VPN page
        {:else}
          {poolSize} config{poolSize === 1 ? '' : 's'} in pool, none active
        {/if}
      </small>
    </div>

    <div class="card">
      <div class="row">
        <span class="icon">{ICON.lock}</span>
        <span>Firewall</span>
        <span class="pill {signinPill(ns.signin).cls}">{signinPill(ns.signin).text}</span>
      </div>
      <small>
        {#if ns.signin?.state === 'open'}
          sign-in window: {ns.signin.remaining_sec}s remaining
        {:else if ns.signin?.strict_mode}
          strict mode — no captive-portal bypass allowed
        {:else}
          LAN→WAN gated by tunnel state
        {/if}
      </small>
    </div>

    <div class="card">
      <div class="row">
        <span class="icon">{ICON.wifi}</span>
        <span>Captive portal</span>
        <span class="pill {captivePill().cls}">{captivePill().text}</span>
      </div>
      <small>
        {#if ns.captive?.captive}
          {(ns.captive.portal_ips ?? []).join(', ') || 'unknown IP'}
        {:else if ns.captive}
          no portal intercepting traffic
        {:else}
          probe pending
        {/if}
      </small>
    </div>

    <div class="card">
      <div class="row">
        <span class="icon">{ICON.key}</span>
        <span>Session</span>
        {#if who?.authenticated}
          <span class="pill ok">credential #{who.credential_id}</span>
        {:else}
          <span class="pill err">none</span>
        {/if}
      </div>
      <small>
        {#if who?.authenticated}
          expires in {fmtExpiry(who.expires_at)}
        {:else}
          not signed in
        {/if}
      </small>
    </div>
  </div>
</section>

<style>
  header {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 12px;
  }
  h2 { margin: 0; font-size: 16px; font-weight: 600; }
  .loaded { color: var(--fg-faint); font-size: 12px; }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
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
  .pill.dim { color: var(--fg-faint); border-color: var(--border); }
  .mono { font-family: var(--font-mono); }

  .led {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    box-shadow: 0 0 8px currentColor;
  }
</style>
