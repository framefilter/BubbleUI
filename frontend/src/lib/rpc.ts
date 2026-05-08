// Thin wrapper around uhttpd's /ubus JSON-RPC endpoint.
//
// In production this hits OpenWRT's rpcd over uhttpd. During M1 we ship
// a mocked transport (see ./mock.ts) so the UI can be developed and
// reviewed without a router on the bench.

import { mockUbus } from './mock';

export interface UbusError {
  code: number;
  message: string;
}

export type UbusResult<T> = { ok: true; data: T } | { ok: false; error: UbusError };

export interface RpcTransport {
  call<T>(object: string, method: string, params?: Record<string, unknown>): Promise<UbusResult<T>>;
}

const useMock = import.meta.env.DEV || import.meta.env.VITE_USE_MOCK === 'true';

const realTransport: RpcTransport = {
  async call<T>(object: string, method: string, params: Record<string, unknown> = {}) {
    const session = sessionStorage.getItem('bubbleui.session') ?? '00000000000000000000000000000000';
    const body = {
      jsonrpc: '2.0',
      id: 1,
      method: 'call',
      params: [session, object, method, params],
    };
    const res = await fetch('/ubus', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      return { ok: false, error: { code: res.status, message: res.statusText } };
    }
    const json = await res.json();
    if (json.error) {
      return { ok: false, error: { code: json.error.code, message: json.error.message } };
    }
    // ubus returns [status, data]
    const [status, data] = json.result as [number, T];
    if (status !== 0) {
      return { ok: false, error: { code: status, message: `ubus status ${status}` } };
    }
    return { ok: true, data };
  },
};

export const rpc: RpcTransport = useMock ? mockUbus : realTransport;
