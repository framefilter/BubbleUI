<script lang="ts">
  // Per DESIGN.md §6.5 the captive-portal sign-in window must be
  // visible on EVERY screen, not just the WiFi pane — it's a
  // security-relevant state and easy to forget about. This banner
  // mounts in App.svelte above the main content and renders only
  // when the window is open.

  import { net, closeSignin } from '../lib/netStore.svelte';
  import { ICON } from '../lib/icons';

  const s = net();

  function fmtRemaining(sec: number): string {
    const m = Math.floor(sec / 60);
    const r = Math.max(0, sec - m * 60);
    return m + 'm ' + r.toString().padStart(2, '0') + 's';
  }
</script>

{#if s.signin?.state === 'open'}
  <div class="banner" role="status" aria-live="polite">
    <span class="icon">{ICON.warn}</span>
    <div class="text">
      <strong>Sign-in window open</strong>
      <span class="rem">— {fmtRemaining(s.signin.remaining_sec ?? 0)} remaining</span>
      <div class="detail">
        LAN→WAN allowed to
        <code>{(s.signin.portal_ips ?? []).join(', ') || '—'}</code>
        on TCP <code>{(s.signin.allowed_ports ?? []).join(', ')}</code>.
      </div>
    </div>
    <button onclick={closeSignin} class="close">Close now</button>
  </div>
{/if}

<style>
  .banner {
    display: grid;
    grid-template-columns: auto 1fr auto;
    gap: 12px;
    align-items: center;
    background: color-mix(in srgb, var(--accent-warn) 18%, var(--bg-elev));
    border: 1px solid var(--accent-warn);
    border-radius: var(--radius);
    padding: 10px 12px;
    margin-bottom: 12px;
    color: var(--fg);
    font-size: 13px;
  }
  .banner .icon { color: var(--accent-warn); font-size: 16px; }
  .text { line-height: 1.4; }
  .rem { color: var(--accent-warn); font-weight: 600; }
  .detail { color: var(--fg-dim); font-size: 12px; }
  code { background: var(--bg); padding: 1px 4px; border-radius: 3px; }
  .close {
    background: var(--bg-elev);
    border-color: var(--accent-warn);
    color: var(--accent-warn);
  }
</style>
