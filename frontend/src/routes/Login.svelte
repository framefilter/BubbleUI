<script lang="ts">
  import { login } from '../lib/session.svelte';
  import { ICON } from '../lib/icons';

  let password = $state('');
  let error = $state('');
  let busy = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    error = '';
    busy = true;
    const result = await login(password);
    busy = false;
    if (!result.ok) error = result.reason ?? 'login failed';
  }
</script>

<div class="login">
  <form onsubmit={submit}>
    <h1><span class="icon">{ICON.router}</span> BubbleUI</h1>
    <p class="hint">
      Plug in your hardware key and enter your admin password.
    </p>

    <label>
      <span>Password</span>
      <input
        type="password"
        autocomplete="current-password"
        bind:value={password}
        autofocus
      />
    </label>

    <button type="submit" disabled={busy}>
      {#if busy}
        <span class="icon spin">{ICON.refresh}</span> verifying key
      {:else}
        <span class="icon">{ICON.key}</span> sign in
      {/if}
    </button>

    {#if error}
      <p class="err"><span class="icon">{ICON.err}</span> {error}</p>
    {/if}

    <p class="recovery">
      <a href="#/recover">Lost my key</a>
    </p>
  </form>
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
  .hint { color: var(--fg-dim); margin: 0; font-size: 13px; }
  label { display: grid; gap: 6px; }
  label span { color: var(--fg-dim); font-size: 12px; }
  .err { color: var(--accent-err); margin: 0; font-size: 13px; }
  .recovery { margin: 0; text-align: center; }
  .recovery a { color: var(--fg-dim); font-size: 12px; }
  .spin { display: inline-block; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
