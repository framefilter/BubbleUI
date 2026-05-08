// Session state. M1 ships a fake login that accepts any non-empty password
// and pretends a YubiKey was plugged in. Real flow lands in M2 (see
// DESIGN.md §5).

interface SessionState {
  authenticated: boolean;
  user: string | null;
  hasKey: boolean;
}

let state: SessionState = $state({
  authenticated: false,
  user: null,
  hasKey: false,
});

export function session(): SessionState {
  return state;
}

export async function login(password: string): Promise<{ ok: boolean; reason?: string }> {
  if (!password) return { ok: false, reason: 'password required' };
  await new Promise((r) => setTimeout(r, 200));
  // M1 mock: pretend the router saw a YubiKey on USB and got a valid HMAC.
  state.authenticated = true;
  state.user = 'admin';
  state.hasKey = true;
  return { ok: true };
}

export function logout(): void {
  state.authenticated = false;
  state.user = null;
  state.hasKey = false;
}
