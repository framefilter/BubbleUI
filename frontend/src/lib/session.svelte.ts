// Session state shared across the SPA. Backed by the real
// /auth/session/whoami, /auth/yubikey/login, /auth/session/logout, and
// /auth/recover endpoints exposed by bubble-authd.

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

export async function loginYubiKey(): Promise<{ ok: boolean; reason?: string }> {
  const r = await api.yubikeyLogin();
  if (!r.ok) {
    state.lastError = r.error.error;
    return { ok: false, reason: r.error.error };
  }
  state.authenticated = true;
  state.credentialId = r.data.credential_id;
  state.expiresAt = r.data.expires_at;
  state.lastError = null;
  return { ok: true };
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
