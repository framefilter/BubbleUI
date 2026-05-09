<script lang="ts">
  import { ICON } from '../lib/icons';
  import { refresh } from '../lib/session.svelte';

  let busy = $state(false);

  async function recheck() {
    busy = true;
    await refresh();
    busy = false;
  }
</script>

<div class="setup">
  <div class="card">
    <h1><span class="icon">{ICON.warn}</span> Setup required</h1>

    <p>
      This router has no security credentials registered yet. Until at
      least one is in place, BubbleUI cannot let you sign in.
    </p>

    <p class="instruction">
      From a shell on the router, run:
    </p>
    <pre>bubble-authd provision</pre>
    <p class="hint">
      You'll be shown a one-time recovery code and a 40-character secret
      to program your YubiKey's HMAC slot 2:
    </p>
    <pre>ykman otp chalresp --touch 2 &lt;hex-secret&gt;</pre>

    <p class="hint">
      Once you've programmed your key, plug it into the router's USB port
      and click below to retry.
    </p>

    <button onclick={recheck} disabled={busy}>
      {#if busy}
        <span class="icon spin">{ICON.refresh}</span> checking
      {:else}
        <span class="icon">{ICON.refresh}</span> I've provisioned a credential
      {/if}
    </button>

    <p class="footer">
      The full first-boot wizard described in DESIGN.md §6.7 lands later.
      For now, provisioning runs from the CLI.
    </p>
  </div>
</div>

<style>
  .setup {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 16px;
  }
  .card {
    width: 100%;
    max-width: 480px;
    display: grid;
    gap: 12px;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
  }
  h1 { margin: 0; font-size: 18px; font-weight: 600; }
  p { margin: 0; line-height: 1.5; font-size: 14px; }
  .instruction { margin-top: 4px; }
  .hint { color: var(--fg-dim); font-size: 13px; }
  .footer { color: var(--fg-faint); font-size: 12px; margin-top: 8px; }
  pre {
    margin: 0;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 10px 12px;
    font-size: 13px;
    overflow-x: auto;
  }
  .spin { display: inline-block; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
