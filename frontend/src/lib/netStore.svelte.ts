// Shared store that polls bubble-netd's /net/signin/status. Multiple
// components subscribe (the global SigninBanner, the WiFi page's
// captive-portal card, possibly future settings panels). DESIGN.md
// §6.5 requires the open-window state to be visible on EVERY screen,
// which is what this store + the banner mounted in App.svelte deliver.

import * as api from './api';
import type { CaptiveStatus, SigninStatus } from './api';

interface NetState {
  signin: SigninStatus | null;
  captive: CaptiveStatus | null;
  // Last error string surfaced from any net call. Cleared on success.
  lastError: string | null;
}

const state: NetState = $state({ signin: null, captive: null, lastError: null });

export function net(): NetState {
  return state;
}

export async function refreshSignin(): Promise<void> {
  const r = await api.netSigninStatus();
  if (r.ok) {
    state.signin = r.data;
    state.lastError = null;
  } else {
    state.lastError = r.error.error;
  }
}

export async function refreshCaptive(): Promise<void> {
  const r = await api.netCaptive();
  if (r.ok) {
    state.captive = r.data;
  }
}

export async function openSignin(portalIPs: string[], durationSec?: number) {
  const r = await api.netSigninOpen(portalIPs, durationSec);
  await refreshSignin();
  return r;
}

export async function closeSignin() {
  const r = await api.netSigninClose();
  await refreshSignin();
  return r;
}

let pollHandle: ReturnType<typeof setInterval> | null = null;

// Start a low-frequency background poll. The banner subscribes to the
// resulting state via Svelte runes. Idempotent.
export function startPolling(intervalMs = 5000): () => void {
  if (pollHandle !== null) return () => {};
  void refreshSignin();
  pollHandle = setInterval(() => {
    void refreshSignin();
  }, intervalMs);
  return () => {
    if (pollHandle !== null) {
      clearInterval(pollHandle);
      pollHandle = null;
    }
  };
}
