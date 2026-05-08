// In-memory mock of the ubus calls the UI needs. Mirrors the ACL surface
// drafted in DESIGN.md §8.2. Replace with the real transport (rpc.ts)
// once we're running on a router.

import type { RpcTransport, UbusResult } from './rpc';

const wifiNetworks = [
  { ssid: 'Hotel-Guest',      signal: -52, encryption: 'open',  bssid: '00:11:22:33:44:55' },
  { ssid: 'Hotel-Premium',    signal: -61, encryption: 'wpa2',  bssid: '00:11:22:33:44:56' },
  { ssid: 'Starbucks WiFi',   signal: -73, encryption: 'open',  bssid: 'aa:bb:cc:dd:ee:01' },
  { ssid: 'definitely-not-a-cop', signal: -78, encryption: 'wpa3', bssid: 'aa:bb:cc:dd:ee:02' },
];

const state = {
  wan: { up: true, address: '10.0.0.42', uptime: 1284 },
  wwan: { up: false, ssid: null as string | null, signal: 0 },
  wg: { up: false, peer: null as string | null, handshake_age: null as number | null },
  ap: { ssid: 'Bubble-Trip', encryption: 'sae', isolation: true, clients: 0 },
  dns: { provider: 'quad9', mode: 'doh' as 'doh' | 'dot', enforced: true },
};

async function delay<T>(value: T, ms = 120): Promise<T> {
  await new Promise((r) => setTimeout(r, ms));
  return value;
}

export const mockUbus: RpcTransport = {
  async call<T>(object: string, method: string, params: Record<string, unknown> = {}): Promise<UbusResult<T>> {
    const key = `${object}.${method}`;

    switch (key) {
      case 'system.info':
        return { ok: true, data: await delay({ uptime: 84620, load: [0.1, 0.08, 0.05], memory: { total: 268435456, free: 142000000 } }) as T };

      case 'system.board':
        return { ok: true, data: await delay({ model: 'Generic OpenWRT (mock)', release: { version: '23.05.5' } }) as T };

      case 'network.interface.dump':
        return { ok: true, data: await delay({ interface: [
          { interface: 'wan',  up: state.wan.up,  'ipv4-address': [{ address: state.wan.address, mask: 24 }] },
          { interface: 'wwan', up: state.wwan.up },
          { interface: 'wg0',  up: state.wg.up },
        ]}) as T };

      case 'iwinfo.scan':
        return { ok: true, data: await delay({ results: wifiNetworks }) as T };

      case 'wireless.connect': {
        const ssid = (params.ssid as string) ?? 'unknown';
        state.wwan.up = true;
        state.wwan.ssid = ssid;
        state.wwan.signal = -55;
        return { ok: true, data: await delay({ connected: true, ssid }) as T };
      }

      case 'wireless.ap.update': {
        if (typeof params.ssid === 'string') state.ap.ssid = params.ssid;
        if (typeof params.isolation === 'boolean') state.ap.isolation = params.isolation;
        return { ok: true, data: await delay({ ok: true }) as T };
      }

      case 'wireguard.status':
        return { ok: true, data: await delay({ ...state.wg }) as T };

      case 'wireguard.up': {
        state.wg.up = true;
        state.wg.peer = (params.peer as string) ?? 'demo.example';
        state.wg.handshake_age = 3;
        return { ok: true, data: await delay({ ok: true }) as T };
      }

      case 'wireguard.down':
        state.wg.up = false;
        state.wg.peer = null;
        state.wg.handshake_age = null;
        return { ok: true, data: await delay({ ok: true }) as T };

      case 'dns.status':
        return { ok: true, data: await delay({ ...state.dns }) as T };

      case 'dns.update': {
        if (typeof params.provider === 'string') state.dns.provider = params.provider;
        if (params.mode === 'doh' || params.mode === 'dot') state.dns.mode = params.mode;
        if (typeof params.enforced === 'boolean') state.dns.enforced = params.enforced;
        return { ok: true, data: await delay({ ...state.dns }) as T };
      }

      default:
        return { ok: false, error: { code: -32601, message: `mock: unknown method ${key}` } };
    }
  },
};
