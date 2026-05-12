<script lang="ts">
  // First-boot wizard implementing DESIGN.md §6.7. Four interactive
  // steps:
  //
  //   1. Welcome
  //   2. Register a WebAuthn security key
  //   3. Recovery code with type-back confirmation
  //   4. Done
  //
  // The optional "WG configs", "uplink", and "SSH" steps from §6.7 land
  // when their backing daemons exist (they don't yet); for now this
  // wizard only handles the parts gated by bubble-authd.

  import { ICON } from '../lib/icons';
  import * as api from '../lib/api';
  import { refresh } from '../lib/session.svelte';

  type Step = 'welcome' | 'key' | 'recovery' | 'done';

  let step = $state<Step>('welcome');
  let busy = $state(false);
  let error = $state('');

  // Set after the credential is registered. Recovery code is shown to
  // the user once and never persisted client-side.
  let recoveryCode = $state('');

  // Type-back state: user must re-enter the recovery code to advance.
  let typeBack = $state('');
  const matches = $derived(
    normalize(typeBack) === normalize(recoveryCode) && recoveryCode.length > 0,
  );

  function normalize(s: string): string {
    return s.replace(/[\s-]/g, '').toUpperCase();
  }

  async function registerWebAuthn() {
    error = '';
    busy = true;
    const begin = await api.webauthnRegisterBegin();
    if (!begin.ok) {
      busy = false;
      error = begin.error.error;
      return;
    }
    const opts = (begin.data.options as { publicKey: PublicKeyCredentialCreationOptions })
      .publicKey;

    // The fields go-webauthn returns are base64url-encoded strings; the
    // browser's WebAuthn API needs them as ArrayBuffers.
    const decoded: PublicKeyCredentialCreationOptions = {
      ...opts,
      challenge: b64uToBuffer(opts.challenge as unknown as string),
      user: { ...opts.user, id: b64uToBuffer(opts.user.id as unknown as string) },
      excludeCredentials: opts.excludeCredentials?.map((c) => ({
        ...c,
        id: b64uToBuffer(c.id as unknown as string),
      })),
    };

    let credential: Credential | null = null;
    try {
      credential = await navigator.credentials.create({ publicKey: decoded });
    } catch (e) {
      busy = false;
      error = (e as Error).message ?? 'browser rejected the registration';
      return;
    }
    if (!credential) {
      busy = false;
      error = 'browser returned no credential';
      return;
    }
    const cred = credential as PublicKeyCredential;
    const att = cred.response as AuthenticatorAttestationResponse;
    const payload = {
      id: cred.id,
      rawId: bufferToB64u(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bufferToB64u(att.attestationObject),
        clientDataJSON: bufferToB64u(att.clientDataJSON),
      },
    };

    const finish = await api.webauthnRegisterFinish(begin.data.handle, payload, 'this browser');
    busy = false;
    if (!finish.ok) {
      error = finish.error.error;
      return;
    }
    if (!finish.data.recovery_code) {
      error = 'server did not return a recovery code (unexpected for first credential)';
      return;
    }
    recoveryCode = finish.data.recovery_code;
    step = 'recovery';
  }

  async function finish() {
    busy = true;
    await refresh();
    busy = false;
    step = 'done';
  }

  // base64url helpers — WebAuthn flows use this encoding everywhere.
  function b64uToBuffer(s: string): ArrayBuffer {
    const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
    const bin = atob(padded);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }
  function bufferToB64u(buf: ArrayBuffer): string {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
</script>

<div class="wizard">
  <div class="card">
    <header>
      <h1><span class="icon">{ICON.router}</span> BubbleUI setup</h1>
      <ol class="steps">
        <li class:active={step === 'welcome'} class:done={step !== 'welcome'}>Welcome</li>
        <li class:active={step === 'key'} class:done={step === 'recovery' || step === 'done'}>Security key</li>
        <li class:active={step === 'recovery'} class:done={step === 'done'}>Recovery code</li>
        <li class:active={step === 'done'}>Done</li>
      </ol>
    </header>

    {#if step === 'welcome'}
      <p>
        Welcome. This wizard will set up the credential you'll use to
        sign into BubbleUI. It takes about three minutes and you'll need
        a device with a FIDO2 authenticator — Touch ID, Windows Hello,
        an Android device, or a hardware security key (YubiKey 5+,
        SoloKey, etc.) plugged into <em>this</em> device.
      </p>
      <button onclick={() => (step = 'key')}>
        Get started <span class="icon">{ICON.bolt}</span>
      </button>
    {:else if step === 'key'}
      <p>Register a security key for this router.</p>

      <div class="choices">
        <div class="choice selected">
          <div>
            <strong><span class="icon">{ICON.shield}</span> WebAuthn from this browser</strong>
            <p>
              Your browser will prompt you to use this device's
              authenticator (Touch ID, Windows Hello, FIDO2 key, etc.).
              You can register more devices later from settings.
            </p>
          </div>
        </div>
      </div>

      {#if error}
        <p class="err"><span class="icon">{ICON.err}</span> {error}</p>
      {/if}

      <div class="actions">
        <button onclick={() => (step = 'welcome')} class="secondary">Back</button>
        <button onclick={registerWebAuthn} disabled={busy}>
          {busy ? 'waiting for browser…' : 'register & continue'}
        </button>
      </div>
    {:else if step === 'recovery'}
      <h2><span class="icon">{ICON.warn}</span> Save your recovery code</h2>

      <p>
        This is the <strong>only</strong> way to recover access if you
        lose every registered credential. Write it down and store it
        somewhere separate from the router. It will not be shown again.
      </p>

      <pre class="recovery-code">{recoveryCode}</pre>

      <p class="hint">
        Type it back to confirm you've saved it. Dashes and case don't
        matter.
      </p>
      <input
        type="text"
        autocomplete="off"
        autocapitalize="characters"
        spellcheck="false"
        bind:value={typeBack}
        placeholder="paste or type the code"
      />

      <div class="actions">
        <button disabled={!matches || busy} onclick={finish}>
          {matches ? "I've saved it — finish" : 'enter the code to continue'}
        </button>
      </div>
    {:else if step === 'done'}
      <h2><span class="icon">{ICON.ok}</span> Setup complete</h2>
      <p>
        Your router is ready. Sign in with your security key from the
        next screen.
      </p>
      <button onclick={() => (window.location.hash = '/')}>Continue</button>
    {/if}
  </div>
</div>

<style>
  .wizard {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 16px;
  }
  .card {
    width: 100%;
    max-width: 540px;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
    display: grid;
    gap: 14px;
  }
  header { display: grid; gap: 8px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
  h1 { margin: 0; font-size: 18px; font-weight: 600; }
  h2 { margin: 0; font-size: 16px; font-weight: 600; }
  p  { margin: 0; line-height: 1.5; font-size: 14px; }
  .hint { color: var(--fg-dim); font-size: 13px; }
  .err  { color: var(--accent-err); font-size: 13px; }
  pre {
    margin: 0;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 10px 12px;
    font-size: 13px;
    overflow-x: auto;
  }
  .recovery-code {
    text-align: center;
    font-size: 18px;
    letter-spacing: 1px;
    padding: 16px;
    border: 1px solid var(--accent-warn);
    color: var(--accent-warn);
  }

  .steps {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    gap: 4px;
    font-size: 11px;
    color: var(--fg-faint);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .steps li {
    flex: 1;
    border-bottom: 2px solid var(--border);
    padding-bottom: 4px;
  }
  .steps li.active { color: var(--fg); border-color: var(--accent-ok); }
  .steps li.done { color: var(--accent-ok); border-color: var(--accent-ok); }

  .choices { display: grid; gap: 8px; }
  .choice {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 12px;
    align-items: start;
    padding: 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    cursor: pointer;
  }
  .choice:hover { border-color: var(--fg-dim); }
  .choice.selected { border-color: var(--accent-ok); background: color-mix(in srgb, var(--accent-ok) 8%, transparent); }
  .choice input { width: auto; margin-top: 4px; }
  .choice strong { display: inline-flex; align-items: center; gap: 6px; }
  .choice p { color: var(--fg-dim); font-size: 12px; margin-top: 4px; }

  .actions { display: flex; gap: 8px; justify-content: flex-end; }
  button.secondary { background: transparent; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
