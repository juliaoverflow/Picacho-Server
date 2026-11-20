<script>
  // Edits config.toml: everything read at startup (listeners, TLS, storage,
  // process limits, logging). Saving writes the file (with a .bak copy);
  // a restart applies it.
  import { onMount } from 'svelte';
  import { get, put, post } from '../lib/api.js';
  import { ui, restartServer } from '../lib/ui.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import Icon from '../lib/Icon.svelte';
  import Toggle from '../lib/Toggle.svelte';

  let info = $state(null);
  let cfg = $state(null);
  let original = $state('');
  let tab = $state('network');
  let raw = $state('');
  let rawDirty = $state(false);
  let saving = $state(false);
  let lists = $state({});

  const LISTS = [
    ['listen', 'smtp'], ['listen', 'submission'], ['listen', 'submissions'], ['listen', 'imap'], ['listen', 'imaps'],
    ['web', 'listen'], ['web', 'trusted_proxies'], ['listen', 'proxy_protocol_from'],
  ];

  async function load() {
    info = await get('/admin/config');
    const base = info.saved ?? info.running;
    cfg = JSON.parse(JSON.stringify(base));
    cfg.storage.attachments ??= null;
    for (const [a, b] of LISTS) lists[`${a}.${b}`] = (cfg[a][b] ?? []).join('\n');
    original = JSON.stringify(cfg);
    raw = info.toml || '# config.toml does not exist yet. Every setting is optional.\n';
    rawDirty = false;
    ui.restartRequired = info.restart_required;
  }
  onMount(() => load().catch((e) => toast.error(e)));

  function syncLists() {
    for (const [a, b] of LISTS) {
      cfg[a][b] = (lists[`${a}.${b}`] ?? '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
    }
  }
  const dirty = $derived.by(() => {
    if (!cfg) return false;
    const copy = JSON.parse(JSON.stringify(cfg));
    for (const [a, b] of LISTS) copy[a][b] = (lists[`${a}.${b}`] ?? '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
    return JSON.stringify(copy) !== original;
  });

  /** "" means "not set" for optional fields. */
  function clean(v, key = '') {
    if (Array.isArray(v)) return v.map((x) => clean(x));
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, clean(x, k)]));
    if (v === '' && !['bucket', 'level', 'format'].includes(key)) return null;
    return v;
  }

  async function save() {
    syncLists();
    saving = true;
    try {
      await put('/admin/config', { config: clean(cfg) });
      toast.ok('Saved config.toml. Restart to apply.');
      await load();
      ui.restartRequired = true;
    } catch (e) {
      toast.error(e);
    } finally {
      saving = false;
    }
  }

  async function saveRaw() {
    saving = true;
    try {
      await put('/admin/config/raw', { toml: raw });
      toast.ok('Saved config.toml. Restart to apply.');
      await load();
      ui.restartRequired = true;
    } catch (e) {
      toast.error(e);
    } finally {
      saving = false;
    }
  }

  async function restart() {
    try {
      await restartServer(post);
    } catch (e) {
      toast.error(e);
    }
  }

  function ensureS3(target) {
    target.s3 ??= { bucket: '', region: null, endpoint: null, access_key_id: null, secret_access_key: null, secret_access_key_file: null, prefix: null, path_style: false, allow_http: false };
  }
  function toggleAttachments(on) {
    cfg.storage.attachments = on ? { kind: 'local', path: null, s3: null, threshold_bytes: 65536 } : null;
  }

  const TABS = [
    ['network', 'Network', 'globe'],
    ['tls', 'TLS', 'lock'],
    ['storage', 'Storage', 'database'],
    ['limits', 'Limits', 'shield'],
    ['logging', 'Logging & DNS', 'activity'],
    ['toml', 'config.toml', 'edit'],
  ];
</script>

<div class="page"><div class="page-inner">
  <div class="page-head">
    <div>
      <h1>Configuration</h1>
      <p class="muted lead-text">Settings read when the server starts. Changes are written to <code>config.toml</code> and apply after a restart. Day-to-day policy lives on the other pages and applies immediately.</p>
    </div>
  </div>

  {#if info}
    <div class="file card">
      <Icon name="folder" />
      <div class="grow"><strong class="mono">{info.path}</strong><span class="muted small">{info.exists ? 'Exists' : 'Not created yet; all defaults are in use'} · {info.writable ? 'writable' : 'not writable by the server'}</span></div>
      {#if ui.restartRequired}<span class="chip warning">Restart pending</span>{/if}
      <button class="btn small" onclick={restart} disabled={ui.restarting}><Icon name="refresh" size={15} /> Restart server</button>
    </div>
    {#if !info.writable}<div class="notice warning"><Icon name="alert" size={18} /><span>The server can't write this file. Give its user write access, or edit the file by hand.</span></div>{/if}

    <div class="tabs" role="tablist">
      {#each TABS as [k, l, i]}
        <button role="tab" class:on={tab === k} aria-selected={tab === k} onclick={() => (tab = k)}><Icon name={i} size={16} /> {l}</button>
      {/each}
    </div>

    {#if tab === 'network'}
      <div class="card">
        <h3>Mail services</h3>
        <p class="sub">Addresses to listen on, one per line (e.g. <code>0.0.0.0:25</code>, <code>[::]:993</code>). Leave empty to turn a service off. Ports below 1024 need root or CAP_NET_BIND_SERVICE.</p>
        <div class="grid3">
          {#each [['smtp', 'SMTP (inbound MX)', '25'], ['submission', 'Submission (STARTTLS)', '587'], ['submissions', 'Submission (TLS)', '465'], ['imap', 'IMAP (STARTTLS)', '143'], ['imaps', 'IMAP (TLS)', '993']] as [k, label, port]}
            <label class="field"><span>{label}</span><textarea class="input mono" rows="2" bind:value={lists[`listen.${k}`]} placeholder={`0.0.0.0:${port}`}></textarea></label>
          {/each}
          <label class="field"><span>Accept PROXY protocol from</span><textarea class="input mono" rows="2" bind:value={lists['listen.proxy_protocol_from']} placeholder="10.0.0.0/8"></textarea></label>
        </div>
      </div>
      <div class="card">
        <h3>Web console & JMAP</h3>
        <div class="grid2">
          <label class="field"><span>Listen on</span><textarea class="input mono" rows="2" bind:value={lists['web.listen']} placeholder="0.0.0.0:8080"></textarea></label>
          <label class="field"><span>Trusted reverse proxies</span><textarea class="input mono" rows="2" bind:value={lists['web.trusted_proxies']} placeholder="127.0.0.1"></textarea><span class="hint">X-Forwarded-For and -Proto are honored only from these.</span></label>
          <label class="field"><span>Public URL</span><input class="input" bind:value={cfg.web.public_url} placeholder="https://mail.example.com" /><span class="hint">Used in the startup banner and JMAP session URLs.</span></label>
          <label class="field"><span>Console session length (hours)</span><input class="input" type="number" min="1" bind:value={cfg.web.session_hours} /></label>
        </div>
        <Toggle bind:checked={cfg.web.tls} label="Serve the console over HTTPS" hint="Uses the certificate from the TLS tab. Leave off behind a TLS-terminating proxy." />
      </div>
      <div class="card">
        <h3>Identity</h3>
        <label class="field"><span>Host name at startup</span><input class="input" bind:value={cfg.hostname} placeholder="Machine host name" /><span class="hint">The Settings page can override it while running.</span></label>
      </div>
    {:else if tab === 'tls'}
      <div class="card">
        <h3>Certificate</h3>
        <p class="sub">PEM files (for example from Let's Encrypt). Without them a self-signed certificate is generated in the data directory.</p>
        <div class="grid2">
          <label class="field"><span>Certificate chain</span><input class="input mono" bind:value={cfg.tls.cert} placeholder="/etc/letsencrypt/live/mail.example.com/fullchain.pem" /></label>
          <label class="field"><span>Private key</span><input class="input mono" bind:value={cfg.tls.key} placeholder="/etc/letsencrypt/live/mail.example.com/privkey.pem" /></label>
          <label class="field"><span>Minimum TLS version</span>
            <select class="input" bind:value={cfg.tls.min_version}><option value={null}>TLS 1.2 (default)</option><option value="1.3">TLS 1.3</option></select>
          </label>
        </div>
      </div>
    {:else if tab === 'storage'}
      <div class="card">
        <h3>Data directory</h3>
        <label class="field"><span>Base directory</span><input class="input mono" bind:value={cfg.storage.data_dir} /><span class="hint">SQLite, local blobs, generated certificates and keys live here unless placed elsewhere below.</span></label>
        <div class="grid2" style="margin-top:12px">
          <label class="field"><span>Read cache (MB)</span><input class="input" type="number" min="1" bind:value={cfg.storage.cache_mb} /></label>
          <label class="field"><span>Encryption key file</span><input class="input mono" bind:value={cfg.storage.encryption_key_file} placeholder="Generated in the data directory" /></label>
        </div>
        <Toggle bind:checked={cfg.storage.encrypt} label="Encrypt stored mail (AES-256-GCM)" hint="Applies to new messages and attachments. Back up the key: mail is unreadable without it." />
      </div>
      <div class="card">
        <h3>Database</h3>
        <p class="sub">Accounts, folders, flags and the queue.</p>
        <div class="segmented"><button class:on={cfg.storage.database.kind === 'sqlite'} onclick={() => (cfg.storage.database.kind = 'sqlite')}>SQLite</button><button class:on={cfg.storage.database.kind === 'postgres'} onclick={() => (cfg.storage.database.kind = 'postgres')}>PostgreSQL</button></div>
        <div class="grid2" style="margin-top:12px">
          <label class="field"><span>Connection URL</span><input class="input mono" type="password" bind:value={cfg.storage.database.url} placeholder={cfg.storage.database.kind === 'postgres' ? 'postgres://user:pass@host/db' : 'Default: data_dir/mail.db'} /></label>
          <label class="field"><span>…or read URL from file</span><input class="input mono" bind:value={cfg.storage.database.url_file} placeholder="/run/secrets/db-url" /></label>
          <label class="field"><span>Max connections</span><input class="input" type="number" min="2" bind:value={cfg.storage.database.max_connections} /></label>
        </div>
      </div>
      {#each [['messages', 'Messages', cfg.storage.messages], ['attachments', 'Attachments', cfg.storage.attachments]] as [key, title, target]}
        <div class="card">
          <div class="row"><h3>{title}</h3><span class="spacer"></span>
            {#if key === 'attachments'}<Toggle checked={!!cfg.storage.attachments} label="Store separately" onchange={toggleAttachments} />{/if}
          </div>
          {#if target}
            <p class="sub">{key === 'messages' ? 'Raw messages, deduplicated by content.' : 'Attachments over the threshold are split out of messages and shared across mailboxes.'}</p>
            <div class="segmented">
              {#each [['local', 'Local disk'], ['s3', 'S3-compatible'], ['database', 'Database']] as [k, l]}
                <button class:on={target.kind === k} onclick={() => { target.kind = k; if (k === 's3') ensureS3(target); }}>{l}</button>
              {/each}
            </div>
            <div class="grid2" style="margin-top:12px">
              {#if target.kind === 'local'}
                <label class="field"><span>Directory</span><input class="input mono" bind:value={target.path} placeholder={`data_dir/${key}`} /></label>
              {:else if target.kind === 's3' && target.s3}
                <label class="field"><span>Bucket</span><input class="input" bind:value={target.s3.bucket} /></label>
                <label class="field"><span>Region</span><input class="input" bind:value={target.s3.region} placeholder="us-east-1" /></label>
                <label class="field"><span>Endpoint</span><input class="input mono" bind:value={target.s3.endpoint} placeholder="https://…  (R2, MinIO, B2)" /></label>
                <label class="field"><span>Key prefix</span><input class="input mono" bind:value={target.s3.prefix} /></label>
                <label class="field"><span>Access key ID</span><input class="input mono" bind:value={target.s3.access_key_id} /></label>
                <label class="field"><span>Secret key file</span><input class="input mono" bind:value={target.s3.secret_access_key_file} placeholder="/run/secrets/s3" /><span class="hint">Preferred over putting the secret in config.toml.</span></label>
                <label class="field"><span>Secret key</span><input class="input mono" type="password" bind:value={target.s3.secret_access_key} /></label>
              {/if}
              {#if key === 'attachments'}
                <label class="field"><span>Threshold (bytes)</span><input class="input" type="number" min="1024" bind:value={target.threshold_bytes} /></label>
              {/if}
            </div>
            {#if target.kind === 's3' && target.s3}
              <Toggle bind:checked={target.s3.path_style} label="Path-style URLs" hint="Needed for MinIO and most self-hosted stores." />
              <Toggle bind:checked={target.s3.allow_http} label="Allow plain HTTP endpoint" hint="Local testing only." />
            {/if}
          {:else}
            <p class="sub">Attachments are stored inside messages.</p>
          {/if}
        </div>
      {/each}
      <div class="card">
        <h3>Live settings</h3>
        <p class="sub">Where the settings you change in this console are kept.</p>
        <div class="segmented"><button class:on={cfg.storage.settings.kind === 'database'} onclick={() => (cfg.storage.settings.kind = 'database')}>Database</button><button class:on={cfg.storage.settings.kind === 'file'} onclick={() => (cfg.storage.settings.kind = 'file')}>TOML file</button></div>
        {#if cfg.storage.settings.kind === 'file'}
          <label class="field" style="margin-top:12px"><span>File</span><input class="input mono" bind:value={cfg.storage.settings.path} placeholder="data_dir/live.toml" /></label>
        {/if}
        <p class="hint" style="margin-top:10px">Changing storage locations doesn't move existing data. Copy it first, then restart.</p>
      </div>
    {:else if tab === 'limits'}
      <div class="card">
        <h3>Process limits</h3>
        <p class="sub">Hard ceilings that protect the server. Message size, quotas and send rates are under Storage & limits.</p>
        <div class="grid2">
          <label class="field"><span>Max connections</span><input class="input" type="number" min="1" bind:value={cfg.limits.max_connections} /></label>
          <label class="field"><span>Max connections per IP</span><input class="input" type="number" min="1" bind:value={cfg.limits.max_connections_per_ip} /></label>
          <label class="field"><span>IMAP max line (bytes)</span><input class="input" type="number" min="1024" bind:value={cfg.limits.imap_max_line} /></label>
          <label class="field"><span>SMTP max line (bytes)</span><input class="input" type="number" min="512" bind:value={cfg.limits.smtp_max_line} /></label>
          <label class="field"><span>Idle timeout (seconds)</span><input class="input" type="number" min="60" bind:value={cfg.limits.idle_timeout_secs} /></label>
          <label class="field"><span>Login timeout (seconds)</span><input class="input" type="number" min="10" bind:value={cfg.limits.auth_timeout_secs} /></label>
        </div>
      </div>
    {:else if tab === 'logging'}
      <div class="card">
        <h3>Logging</h3>
        <div class="grid2">
          <label class="field"><span>Level or filter</span><input class="input mono" bind:value={cfg.log.level} placeholder="info" /><span class="hint">trace, debug, info, warn, error, or a filter like <code>info,picacho_server=debug</code>.</span></label>
          <label class="field"><span>Format</span><select class="input" bind:value={cfg.log.format}><option value="text">Text</option><option value="json">JSON</option></select></label>
        </div>
      </div>
      <div class="card">
        <h3>DNS resolver</h3>
        <p class="sub">Used for MX lookups, SPF/DKIM/DMARC and block lists.</p>
        <select class="input" style="max-width:280px" bind:value={cfg.dns.resolver}>
          <option value={null}>System resolver</option><option value="cloudflare">Cloudflare</option><option value="google">Google</option><option value="quad9">Quad9</option>
        </select>
      </div>
    {:else}
      <div class="card">
        <div class="row"><h3>config.toml</h3><span class="spacer"></span><span class="hint">Validated before saving · previous version kept as .bak</span></div>
        <textarea class="input mono toml" spellcheck="false" bind:value={raw} oninput={() => (rawDirty = true)}></textarea>
        <div class="row" style="margin-top:12px">
          <button class="btn primary" onclick={saveRaw} disabled={!rawDirty || saving}>Save file</button>
          <button class="btn" onclick={load} disabled={saving}>Revert</button>
        </div>
      </div>
    {/if}

    {#if tab !== 'toml' && dirty}
      <div class="savebar fade-in">
        <span>Unsaved changes to config.toml.</span><span class="spacer"></span>
        <button class="btn small" onclick={load}>Discard</button>
        <button class="btn small primary" onclick={save} disabled={saving}>{saving ? 'Saving…' : 'Save to config.toml'}</button>
      </div>
    {/if}
  {/if}
</div></div>

<style>
  .lead-text { margin: 6px 0 0; max-width: 720px; }
  .file { display: flex; align-items: center; gap: 14px; margin-bottom: 14px !important; }
  .file :global(svg) { color: var(--muted); flex: none; }
  .grow { flex: 1; display: grid; min-width: 0; }
  .grow strong { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 500; }
  .tabs { display: flex; gap: 4px; margin: 4px 0 14px; border-bottom: 1px solid var(--border); overflow-x: auto; }
  .tabs button { display: flex; align-items: center; gap: 7px; padding: 10px 14px; border: 0; background: none; color: var(--muted); cursor: pointer; border-bottom: 2px solid transparent; white-space: nowrap; font-weight: 500; }
  .tabs button.on { color: var(--text); border-bottom-color: var(--accent); }
  .grid3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; }
  .toml { min-height: 420px; font-size: 13px; line-height: 1.5; tab-size: 2; margin-top: 8px; }
  .savebar { position: sticky; bottom: 16px; margin-top: 18px; display: flex; align-items: center; gap: 10px; padding: 10px 12px 10px 18px; border-radius: 12px; background: var(--raised); border: 1px solid var(--border); box-shadow: var(--shadow); }
</style>
