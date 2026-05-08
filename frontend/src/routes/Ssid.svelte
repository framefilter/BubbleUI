<script lang="ts">
  import { rpc } from '../lib/rpc';
  import { ICON } from '../lib/icons';

  let ssid = $state('Bubble-Trip');
  let password = $state('');
  let isolation = $state(true);
  let guestVlan = $state(false);
  let saving = $state(false);
  let saved = $state(false);

  async function save() {
    saving = true;
    saved = false;
    const r = await rpc.call('wireless.ap', 'update', { ssid, isolation });
    saving = false;
    saved = r.ok;
  }

  function genPassword() {
    const a = new Uint8Array(16);
    crypto.getRandomValues(a);
    password = Array.from(a, (b) => b.toString(36)).join('').slice(0, 20);
  }
</script>

<section>
  <h2>Travel SSID</h2>

  <div class="card">
    <label>
      <span>Network name</span>
      <input bind:value={ssid} />
    </label>

    <label>
      <span>Password (WPA3-SAE)</span>
      <div class="row">
        <input type="text" bind:value={password} placeholder="leave empty for open"/>
        <button type="button" onclick={genPassword}><span class="icon">{ICON.key}</span></button>
      </div>
    </label>

    <label class="toggle">
      <input type="checkbox" bind:checked={isolation} />
      <span>
        <strong>Client isolation</strong>
        <small>Devices on this network can't talk to each other. Recommended.</small>
      </span>
    </label>

    <label class="toggle">
      <input type="checkbox" bind:checked={guestVlan} />
      <span>
        <strong>Guest VLAN</strong>
        <small>Separate DHCP scope, zero LAN access. For shared trips.</small>
      </span>
    </label>

    <div class="actions">
      <button onclick={save} disabled={saving}>
        {saving ? 'saving…' : 'save'}
      </button>
      {#if saved}
        <span class="pill ok"><span class="icon">{ICON.ok}</span> saved</span>
      {/if}
    </div>
  </div>

  <p class="note">
    "Forget this trip" wipes the SSID, password, leases, and ARP cache.
    Wire that up in M3.
  </p>
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
  .row { display: flex; gap: 8px; }
  .row input { flex: 1; }

  .toggle {
    grid-template-columns: auto 1fr;
    display: grid;
    gap: 10px;
    align-items: start;
    cursor: pointer;
  }
  .toggle input { width: auto; margin-top: 4px; }
  .toggle small { color: var(--fg-dim); display: block; margin-top: 2px; }

  .actions { display: flex; gap: 8px; align-items: center; }
  .note { color: var(--fg-dim); font-size: 12px; margin-top: 12px; }
</style>
