<script lang="ts">
  import { loginWebAuthn, recover } from '../lib/session.svelte';
  import { ICON } from '../lib/icons';

  let mode = $state<'login' | 'recover'>('login');
  let recoveryCode = $state('');
  let error = $state('');
  let busy = $state(false);

  async function doLogin(e: Event) {
    e.preventDefault();
    error = '';
    busy = true;
    const result = await loginWebAuthn();
    busy = false;
    if (!result.ok) error = result.reason ?? 'login failed';
  }

  async function doRecover(e: Event) {
    e.preventDefault();
    if (!recoveryCode.trim()) {
      error = 'enter your recovery code';
      return;
    }
    error = '';
    busy = true;
    const result = await recover(recoveryCode);
    busy = false;
    if (!result.ok) {
      error = result.reason ?? 'recovery failed';
    } else {
      // Success: state has flipped to setup-mode; the App shell will route.
      recoveryCode = '';
    }
  }
</script>

<div class="login">
  {#if mode === 'login'}
    <form onsubmit={doLogin}>
      <h1><span class="icon">{ICON.router}</span> BubbleUI</h1>
      <p class="hint">
        Use your security key — Touch ID, Windows Hello, or a FIDO2 key
        plugged into this device.
      </p>

      <button type="submit" disabled={busy}>
        {#if busy}
          <span class="icon spin">{ICON.refresh}</span> waiting for key
        {:else}
          <span class="icon">{ICON.key}</span> sign in with security key
        {/if}
      </button>

      {#if error}
        <p class="err"><span class="icon">{ICON.err}</span> {error}</p>
      {/if}

      <p class="alt">
        <button type="button" class="link" onclick={() => { mode = 'recover'; error = ''; }}>
          Lost my keys
        </button>
      </p>
    </form>
  {:else}
    <form onsubmit={doRecover}>
      <h1><span class="icon">{ICON.warn}</span> Recover access</h1>
      <p class="hint">
        Enter the recovery code you saved when you set up this router. Using
        the code <strong>wipes every registered credential</strong> and
        returns the device to setup mode. The code is single-use.
      </p>

      <label>
        <span>Recovery code</span>
        <input
          type="text"
          autocomplete="off"
          autocapitalize="characters"
          spellcheck="false"
          bind:value={recoveryCode}
          placeholder="XXXXXX-XXXXXX-XXXXXX-XXXXXX-XX"
        />
      </label>

      <button type="submit" disabled={busy}>
        {#if busy}
          <span class="icon spin">{ICON.refresh}</span> verifying
        {:else}
          <span class="icon">{ICON.unlock}</span> recover and reset credentials
        {/if}
      </button>

      {#if error}
        <p class="err"><span class="icon">{ICON.err}</span> {error}</p>
      {/if}

      <p class="alt">
        <button type="button" class="link" onclick={() => { mode = 'login'; error = ''; }}>
          Back to sign in
        </button>
      </p>
    </form>
  {/if}
</div>

<style>
  .login {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 16px;
  }
  form {
    width: 100%;
    max-width: 360px;
    display: grid;
    gap: 14px;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
  }
  h1 { margin: 0; font-size: 20px; font-weight: 600; }
  .hint { color: var(--fg-dim); margin: 0; font-size: 13px; line-height: 1.5; }
  label { display: grid; gap: 6px; }
  label span { color: var(--fg-dim); font-size: 12px; }
  .err { color: var(--accent-err); margin: 0; font-size: 13px; }
  .alt { margin: 0; text-align: center; }
  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--fg-dim);
    font-size: 12px;
    cursor: pointer;
    text-decoration: underline;
  }
  .link:hover { color: var(--fg); }
  .spin { display: inline-block; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
