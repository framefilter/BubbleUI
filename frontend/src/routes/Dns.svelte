<script lang="ts">
  import { onMount } from 'svelte';
  import { rpc } from '../lib/rpc';
  import { ICON } from '../lib/icons';

  interface DnsStatus { provider: string; mode: 'doh' | 'dot'; enforced: boolean }

  const providers = [
    { id: 'quad9',      label: 'Quad9 (default, blocks malware)' },
    { id: 'cloudflare', label: 'Cloudflare 1.1.1.1' },
    { id: 'mullvad',    label: 'Mullvad' },
    { id: 'nextdns',    label: 'NextDNS' },
    { id: 'custom',     label: 'Custom…' },
  ];

  let status = $state<DnsStatus | null>(null);
  let saving = $state(false);

  async function refresh() {
    const r = await rpc.call<DnsStatus>('dns', 'status');
    if (r.ok) status = r.data;
  }

  async function update(patch: Partial<DnsStatus>) {
    if (!status) return;
    saving = true;
    const r = await rpc.call<DnsStatus>('dns', 'update', patch);
    saving = false;
    if (r.ok) status = r.data;
  }

  onMount(refresh);
</script>

<section>
  <h2>Encrypted DNS</h2>

  {#if status}
    <div class="card">
      <label>
        <span>Provider</span>
        <select
          value={status.provider}
          onchange={(e) => update({ provider: (e.target as HTMLSelectElement).value })}
        >
          {#each providers as p}
            <option value={p.id}>{p.label}</option>
          {/each}
        </select>
      </label>

      <label>
        <span>Transport</span>
        <select
          value={status.mode}
          onchange={(e) => update({ mode: (e.target as HTMLSelectElement).value as 'doh' | 'dot' })}
        >
          <option value="doh">DNS over HTTPS</option>
          <option value="dot">DNS over TLS</option>
        </select>
      </label>

      <label class="toggle">
        <input
          type="checkbox"
          checked={status.enforced}
          onchange={(e) => update({ enforced: (e.target as HTMLInputElement).checked })}
        />
        <span>
          <strong>Enforce</strong>
          <small>
            Block outbound port 53 from LAN to anything except the local resolver.
            Stops apps that hardcode <code>8.8.8.8</code>.
          </small>
        </span>
      </label>

      {#if saving}
        <small class="saving">saving…</small>
      {/if}
    </div>
  {:else}
    <p>Loading…</p>
  {/if}
</section>

<style>
  h2 { margin: 0 0 12px 0; font-size: 16px; font-weight: 600; }
  .card {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
    display: grid;
    gap: 14px;
  }
  label { display: grid; gap: 6px; }
  label > span { color: var(--fg-dim); font-size: 12px; }
  code { background: var(--bg); padding: 0 4px; border-radius: 3px; }

  .toggle {
    grid-template-columns: auto 1fr;
    display: grid;
    gap: 10px;
    align-items: start;
    cursor: pointer;
  }
  .toggle input { width: auto; margin-top: 4px; }
  .toggle small { color: var(--fg-dim); display: block; margin-top: 2px; }

  .saving { color: var(--fg-dim); }
</style>
