// Typed client for the BubbleUI HTTP API exposed by `bubble-authd`.
//
// Endpoints documented in backend/README.md and DESIGN.md §5/§6.6.
// All requests are same-origin via the Vite dev proxy or, in production,
// uhttpd's TLS termination on the router. Cookies are sent automatically.

export interface ApiError {
  status: number;
  error: string;
}

export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: ApiError };

async function request<T>(
  method: 'GET' | 'POST',
  path: string,
  body?: unknown,
): Promise<ApiResult<T>> {
  const init: RequestInit = {
    method,
    credentials: 'same-origin',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  };
  let res: Response;
  try {
    res = await fetch(path, init);
  } catch (e) {
    return { ok: false, error: { status: 0, error: (e as Error).message ?? 'network error' } };
  }
  let payload: unknown;
  try {
    payload = await res.json();
  } catch {
    payload = null;
  }
  if (!res.ok) {
    const err = (payload as { error?: string } | null)?.error ?? res.statusText;
    return { ok: false, error: { status: res.status, error: err } };
  }
  return { ok: true, data: payload as T };
}

// --- shapes ---

export interface WhoamiAnonymous {
  authenticated: false;
}
export interface WhoamiAuthenticated {
  authenticated: true;
  credential_id: number;
  expires_at: number;
}
export type Whoami = WhoamiAnonymous | WhoamiAuthenticated;

export interface LoginOk {
  credential_id: number;
  expires_at: number;
}

export interface TimeSyncResponse {
  status: string;
  action: 'accepted' | 'skew_detected' | 'applied' | 'skew_unhandled';
  router_time: number;
  browser_time?: number;
  delta_ms: number;
  reason?: string;
}

export interface WebAuthnBegin {
  handle: string;
  // The raw options from go-webauthn. We pass the .publicKey straight to
  // navigator.credentials.{create,get}.
  options: { publicKey: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions };
}

// --- session ---

export const whoami = () => request<Whoami>('GET', '/auth/session/whoami');
export const logout = () => request<{ status: string }>('POST', '/auth/session/logout');
export const setupStatus = () =>
  request<{ has_credentials: boolean }>('GET', '/auth/setup-status');

// --- yubikey ---

export const yubikeyLogin = () => request<LoginOk>('POST', '/auth/yubikey/login');

export interface YubiKeyProvisionOk {
  credential_id: number;
  recovery_code: string;
  not_programmed: boolean;
  // Only present when not_programmed is true:
  secret_hex?: string;
  program_hint?: string;
}

export const yubikeyProvision = () =>
  request<YubiKeyProvisionOk>('POST', '/auth/yubikey/provision', {});

// --- recovery ---

export const recover = (code: string) =>
  request<{ status: string }>('POST', '/auth/recover', { code });

// --- time sync ---

export const timeSync = (now: number, force = false) =>
  request<TimeSyncResponse>('POST', '/api/time/sync', { now, force });

// --- webauthn ---

export const webauthnRegisterBegin = () =>
  request<WebAuthnBegin>('POST', '/auth/webauthn/register/begin', {});

export interface WebAuthnRegisterFinishOk {
  credential_id: number;
  // Returned only when this is the first credential on the device.
  // Display once and never store.
  recovery_code?: string;
}

export const webauthnRegisterFinish = (handle: string, response: unknown, label?: string) =>
  request<WebAuthnRegisterFinishOk>('POST', '/auth/webauthn/register/finish', {
    handle,
    response,
    label,
  });

export const webauthnLoginBegin = () =>
  request<WebAuthnBegin>('POST', '/auth/webauthn/login/begin', {});

export const webauthnLoginFinish = (handle: string, response: unknown) =>
  request<LoginOk>('POST', '/auth/webauthn/login/finish', { handle, response });
