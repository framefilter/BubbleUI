// Session state shared across the SPA. Backed by the real
// /auth/session/whoami, /auth/webauthn/login/{begin,finish},
// /auth/session/logout, and /auth/recover endpoints exposed by
// bubble-authd.

import * as api from './api';

interface SessionState {
  // Tri-state: undefined while we haven't asked the server yet,
  // otherwise the resolved authenticated/anonymous answer.
  authenticated: boolean | undefined;
  credentialId: number | null;
  expiresAt: number | null;
  // True if the device has zero credentials registered → wizard mode.
  // Tri-state same as `authenticated`.
  setupNeeded: boolean | undefined;
  // Last error surfaced from a session-related call. Cleared on success.
  lastError: string | null;
}

const state: SessionState = $state({
  authenticated: undefined,
  credentialId: null,
  expiresAt: null,
  setupNeeded: undefined,
  lastError: null,
});

export function session(): SessionState {
  return state;
}

// refresh hits whoami + setup-status and updates state in one shot.
// Idempotent; safe to call any time.
export async function refresh(): Promise<void> {
  const [who, setup] = await Promise.all([api.whoami(), api.setupStatus()]);

  if (!who.ok) {
    state.authenticated = false;
    state.credentialId = null;
    state.expiresAt = null;
    state.lastError = who.error.error;
  } else if (who.data.authenticated) {
    state.authenticated = true;
    state.credentialId = who.data.credential_id;
    state.expiresAt = who.data.expires_at;
    state.lastError = null;
  } else {
    state.authenticated = false;
    state.credentialId = null;
    state.expiresAt = null;
    state.lastError = null;
  }

  if (setup.ok) {
    state.setupNeeded = !setup.data.has_credentials;
  } else {
    // Failure here is non-fatal — assume the device is provisioned and
    // let the login screen surface the real error.
    state.setupNeeded = false;
  }
}

// loginWebAuthn drives the WebAuthn authentication ceremony end-to-end:
// asks the server for assertion options, hands them to the browser via
// navigator.credentials.get(), and posts the result back. On success
// the server has minted a session cookie which we mirror in state.
export async function loginWebAuthn(): Promise<{ ok: boolean; reason?: string }> {
  const begin = await api.webauthnLoginBegin();
  if (!begin.ok) {
    state.lastError = begin.error.error;
    return { ok: false, reason: begin.error.error };
  }
  const opts = (begin.data.options as { publicKey: PublicKeyCredentialRequestOptions })
    .publicKey;
  const decoded: PublicKeyCredentialRequestOptions = {
    ...opts,
    challenge: b64uToBuffer(opts.challenge as unknown as string),
    allowCredentials: opts.allowCredentials?.map((c) => ({
      ...c,
      id: b64uToBuffer(c.id as unknown as string),
    })),
  };

  let credential: Credential | null = null;
  try {
    credential = await navigator.credentials.get({ publicKey: decoded });
  } catch (e) {
    const msg = (e as Error).message ?? 'browser rejected the sign-in';
    state.lastError = msg;
    return { ok: false, reason: msg };
  }
  if (!credential) {
    const msg = 'browser returned no credential';
    state.lastError = msg;
    return { ok: false, reason: msg };
  }
  const cred = credential as PublicKeyCredential;
  const asr = cred.response as AuthenticatorAssertionResponse;
  const payload = {
    id: cred.id,
    rawId: bufferToB64u(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bufferToB64u(asr.authenticatorData),
      clientDataJSON: bufferToB64u(asr.clientDataJSON),
      signature: bufferToB64u(asr.signature),
      userHandle: asr.userHandle ? bufferToB64u(asr.userHandle) : null,
    },
  };

  const finish = await api.webauthnLoginFinish(begin.data.handle, payload);
  if (!finish.ok) {
    state.lastError = finish.error.error;
    return { ok: false, reason: finish.error.error };
  }
  state.authenticated = true;
  state.credentialId = finish.data.credential_id;
  state.expiresAt = finish.data.expires_at;
  state.lastError = null;
  return { ok: true };
}

// base64url helpers — WebAuthn ceremonies use this encoding for every
// challenge / ID / signature field the browser passes between JS and
// the server. Inlined here so we don't pull a tiny dep just for this.
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

export async function recover(code: string): Promise<{ ok: boolean; reason?: string }> {
  const r = await api.recover(code);
  if (!r.ok) {
    state.lastError = r.error.error;
    return { ok: false, reason: r.error.error };
  }
  state.authenticated = false;
  state.credentialId = null;
  state.expiresAt = null;
  state.lastError = null;
  return { ok: true };
}

export async function logout(): Promise<void> {
  await api.logout();
  state.authenticated = false;
  state.credentialId = null;
  state.expiresAt = null;
  state.lastError = null;
}
