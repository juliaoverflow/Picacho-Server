<script>
  import { onMount } from 'svelte';
  import { post, get } from '../lib/api.js';
  import Icon from '../lib/Icon.svelte';
  import Logo from '../lib/Logo.svelte';
  import Copy from '../lib/Copy.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import { theme } from '../lib/theme.svelte.js';
  import { RELAY_PRESETS } from '../lib/presets.js';

  let { onDone } = $props();

  const STEPS = ['Access key', 'Storage', 'Server', 'Sign-in', 'Outgoing mail', 'Administrator'];
  const SAVE_KEY = 'pm.setup';
  let step = $state(0);
  let busy = $state(false);
  let error = $state('');
  let restarting = $state(false);

  let key = $state('');
  let info = $state(null);
  let storage = $state(null);
  let storageOriginal = '';
  let storageTest = $state(null);
  let hostname = $state('');
  let domain = $state('');
  let method = $state('password');
  let oidc = $state({ display_name: '', issuer: '', client_id: '', client_secret: '', scopes: 'openid email profile' });
  let oidcTest = $state(null);
  let alsoPassword = $state(false);
  let mailPasswords = $state(true);
  let adminName = $state('');
  let adminLocal = $state('postmaster');
  let password = $state('');
  let confirm = $state('');
  let showPw = $state(false);
  let outbound = $state('direct');
  let preset = $state('ses');
  let relay = $state({ host: '', port: 587, tls: 'starttls', username: '', password: '' });

  let me = $state(null);
  let records = $state([]);
  let client = $state(null);

  // Keep progress across the storage restart and the identity-provider round trip.
  function persist() {
    try {
      const { client_secret, ...o } = oidc;
      sessionStorage.setItem(SAVE_KEY, JSON.stringify({ key, step, hostname, domain, method, oidc: o, alsoPassword, mailPasswords, adminName, adminLocal, outbound, preset, relay: { ...relay, password: '' } }));
    } catch {
      /* private mode */
    }
  }
  function forget() {
    try {
      sessionStorage.removeItem(SAVE_KEY);
    } catch {
      /* ignore */
    }
  }

  onMount(async () => {
    const qerr = new URLSearchParams(location.search).get('error');
    let saved = null;
    try {
      saved = JSON.parse(sessionStorage.getItem(SAVE_KEY) || 'null');
    } catch {
      /* ignore */
    }
    if (saved?.key) {
      ({ key, hostname, domain, method, alsoPassword, mailPasswords, adminName, adminLocal, outbound, preset } = saved);
      oidc = { ...oidc, ...saved.oidc };
      relay = { ...relay, ...saved.relay };
      try {
        await loadInfo();
        step = Math.max(saved.step, 2);
      } catch {
        step = 0;
      }
    }
    if (qerr) {
      error = qerr;
      if (step >= 3) step = 5;
    }
  });

  async function loadInfo() {
    info = await post('/setup/verify', { key });
    hostname ||= info.hostname || '';
    domain ||= info.domain || '';
    storage = JSON.parse(JSON.stringify(info.storage_config));
    storage.attachments ??= null;
    storageOriginal = JSON.stringify(storage);
  }

  const strength = $derived.by(() => {
    const p = password;
    let s = 0;
    if (p.length >= (info?.password_min_length ?? 10)) s++;
    if (p.length >= 16) s++;
    if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++;
    if (/\d/.test(p)) s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;
    return Math.min(4, s);
  });

  function formatKey(v) {
    const raw = v.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 25);
    return raw.match(/.{1,5}/g)?.join('-') ?? '';
  }
  function applyPreset(id) {
    preset = id;
    const p = RELAY_PRESETS.find((x) => x.id === id);
    if (p) relay = { ...relay, host: p.host, port: p.port, tls: p.tls, username: p.username ?? relay.username };
  }

  async function verify() {
    busy = true;
    error = '';
    try {
      await loadInfo();
      step = 1;
      persist();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  function cleanStorage() {
    const c = (v, k = '') => {
      if (Array.isArray(v)) return v.map((x) => c(x));
      if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([kk, x]) => [kk, c(x, kk)]));
      return v === '' && k !== 'bucket' ? null : v;
    };
    return c(storage);
  }
  function ensureS3(t) {
    t.s3 ??= { bucket: '', region: null, endpoint: null, access_key_id: null, secret_access_key: null, secret_access_key_file: null, prefix: null, path_style: false, allow_http: false };
  }

  async function testStorage() {
    busy = true;
    storageTest = null;
    try {
      storageTest = await post('/setup/storage/test', { key, storage: cleanStorage() });
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function saveStorage() {
    error = '';
    if (JSON.stringify(storage) === storageOriginal) {
      step = 2;
      persist();
      return;
    }
    busy = true;
    try {
      const r = await post('/setup/storage', { key, storage: cleanStorage() });
      if (!r.restarting) {
        step = 2;
        persist();
        return;
      }
      step = 2;
      persist();
      restarting = true;
      await new Promise((res) => setTimeout(res, 1500));
      for (let i = 0; i < 60; i++) {
        try {
          const s = await get('/status');
          if (s) break;
        } catch {
          /* restarting */
        }
        await new Promise((res) => setTimeout(res, 1000));
      }
      await loadInfo();
      restarting = false;
    } catch (e) {
      error = e.message;
      restarting = false;
    } finally {
      busy = false;
    }
  }

  async function checkProvider() {
    busy = true;
    oidcTest = null;
    try {
      oidcTest = await post('/oidc/test', { key, issuer: oidc.issuer });
    } catch (e) {
      oidcTest = { ok: false, error: e.message };
    } finally {
      busy = false;
    }
  }

  function next() {
    error = '';
    if (step === 2) {
      if (!/^[a-z0-9.-]+\.[a-z0-9-]+$/i.test(hostname.trim()) && hostname.trim() !== 'localhost') return (error = 'Enter the server’s host name, like mail.example.com.');
      if (!/^[a-z0-9.-]+$/i.test(domain.trim()) || (!domain.includes('.') && domain.trim() !== 'localhost')) return (error = 'Enter your mail domain, like example.com.');
    }
    if (step === 3 && method === 'oidc') {
      if (!oidc.issuer.trim() || !oidc.client_id.trim()) return (error = 'Enter the issuer URL and client ID.');
    }
    if (step === 4 && outbound === 'relay' && !relay.host.trim()) return (error = 'Enter the relay host.');
    step += 1;
    persist();
  }

  function body() {
    const b = {
      key,
      hostname: hostname.trim(),
      domain: domain.trim(),
      admin_local: adminLocal.trim(),
      admin_name: adminName.trim(),
      auth: {
        web_password_login: method === 'password' || alsoPassword,
        mail_password_login: mailPasswords,
        oidc: method === 'oidc' ? { ...oidc, enabled: true, display_name: oidc.display_name || 'SSO', client_secret: oidc.client_secret || null } : null,
      },
    };
    if (outbound === 'relay') {
      const p = RELAY_PRESETS.find((x) => x.id === preset);
      b.relay = { id: 'relay', name: p ? p.name : 'Outbound relay', kind: preset === 'cloudflare' ? 'cloudflare' : 'smtp', host: relay.host.trim(), port: Number(relay.port) || 587, tls: relay.tls, username: relay.username || null, password: relay.password || null };
    }
    return b;
  }

  async function finishPassword() {
    if (password.length < (info?.password_min_length ?? 10)) return (error = `Use at least ${info?.password_min_length ?? 10} characters.`);
    if (password !== confirm) return (error = 'The passwords don’t match.');
    busy = true;
    error = '';
    try {
      me = await post('/setup/complete', { ...body(), admin_password: password });
      password = confirm = '';
      forget();
      try {
        const domains = await get('/admin/domains');
        const d = domains.find((x) => x.name === domain.trim());
        if (d) records = (await get(`/admin/domains/${d.id}`)).dns;
        client = await get('/me/client');
      } catch {
        /* optional */
      }
      step = 6;
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function finishOidc() {
    if (!oidc.client_secret) {
      // The secret isn't kept across reloads; ask again if needed.
    }
    busy = true;
    error = '';
    try {
      persist();
      const r = await post('/setup/oidc/begin', body());
      forget();
      location.href = r.redirect;
    } catch (e) {
      error = e.message;
      busy = false;
    }
  }
</script>

<div class="setup">
  <header>
    <div class="brand"><Logo size={26} /><span>Picacho Server</span></div>
    <button class="icon-btn" onclick={() => theme.toggle()} aria-label="Toggle dark mode"><Icon name={theme.dark ? 'sun' : 'moon'} /></button>
  </header>

  <main>
    {#if step < 6}
      <ol class="steps" aria-label="Setup progress">
        {#each STEPS as s, i}
          <li class:done={i < step} class:current={i === step}>
            <span class="bullet">{#if i < step}<Icon name="check" size={13} stroke={2.6} />{:else}{i + 1}{/if}</span>
            <span class="label-text">{s}</span>
          </li>
        {/each}
      </ol>
    {/if}

    <section class="card panel fade-in">
      {#if restarting}
        <div class="center"><Icon name="refresh" size={24} /><h2>Restarting with the new storage…</h2><p class="muted">Setup continues automatically.</p></div>
      {:else if step === 0}
        <h2>Welcome</h2>
        <p class="muted">Enter the access key printed in the server’s console when it started. It proves you control this server, and stops working once setup is finished.</p>
        <form onsubmit={(e) => { e.preventDefault(); verify(); }}>
          <label class="field">
            <span>Access key</span>
            <input class="input mono key" value={key} oninput={(e) => (key = e.target.value = formatKey(e.target.value))}
              placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" autocomplete="off" spellcheck="false" autofocus />
          </label>
          <p class="hint">Not in front of the console? Restart the server and a new key is printed.</p>
          {#if error}<p class="error-text">{error}</p>{/if}
          <div class="actions"><button class="btn primary big" disabled={busy || key.length < 29}>{busy ? 'Checking…' : 'Continue'}</button></div>
        </form>
      {:else if step === 1 && storage}
        <h2>Where mail is stored</h2>
        <p class="muted">Defaults keep everything on this machine. You can also use PostgreSQL and S3-compatible object storage, and keep attachments separately. Saved to <span class="mono">{info?.config_path}</span>.</p>
        <label class="field"><span>Data directory</span><input class="input mono" bind:value={storage.data_dir} /></label>
        <div class="sub-block">
          <div class="label">Database</div>
          <div class="segmented"><button class:on={storage.database.kind === 'sqlite'} onclick={() => (storage.database.kind = 'sqlite')}>SQLite</button><button class:on={storage.database.kind === 'postgres'} onclick={() => (storage.database.kind = 'postgres')}>PostgreSQL</button></div>
          {#if storage.database.kind === 'postgres'}
            <label class="field"><span>Connection URL</span><input class="input mono" type="password" bind:value={storage.database.url} placeholder="postgres://user:pass@host/db" /></label>
          {/if}
        </div>
        {#each [['messages', 'Messages'], ['attachments', 'Large attachments']] as [k, title]}
          <div class="sub-block">
            <div class="label">{title}</div>
            <div class="segmented">
              {#if k === 'attachments'}<button class:on={!storage.attachments} onclick={() => (storage.attachments = null)}>With messages</button>{/if}
              {#each [['local', 'Local disk'], ['s3', 'S3'], ['database', 'Database']] as [kind, l]}
                <button class:on={storage[k]?.kind === kind} onclick={() => { storage[k] ??= { kind, path: null, s3: null, threshold_bytes: 65536 }; storage[k].kind = kind; if (kind === 's3') ensureS3(storage[k]); }}>{l}</button>
              {/each}
            </div>
            {#if storage[k]?.kind === 'local'}
              <label class="field"><span>Directory</span><input class="input mono" bind:value={storage[k].path} placeholder={`data directory/${k}`} /></label>
            {:else if storage[k]?.kind === 's3' && storage[k].s3}
              <div class="grid2">
                <label class="field"><span>Bucket</span><input class="input" bind:value={storage[k].s3.bucket} /></label>
                <label class="field"><span>Region</span><input class="input" bind:value={storage[k].s3.region} placeholder="us-east-1" /></label>
                <label class="field"><span>Endpoint</span><input class="input mono" bind:value={storage[k].s3.endpoint} placeholder="R2, MinIO, B2… (optional)" /></label>
                <label class="field"><span>Access key ID</span><input class="input mono" bind:value={storage[k].s3.access_key_id} /></label>
                <label class="field"><span>Secret key</span><input class="input mono" type="password" bind:value={storage[k].s3.secret_access_key} /></label>
              </div>
              <Toggle bind:checked={storage[k].s3.path_style} label="Path-style URLs (MinIO)" />
            {/if}
          </div>
        {/each}
        <Toggle bind:checked={storage.encrypt} label="Encrypt stored mail (AES-256-GCM)" hint="A key is generated in the data directory. Back it up." />
        {#if storageTest}
          <ul class="tests">
            {#each storageTest.results as r}<li class:bad={!r.ok}><Icon name={r.ok ? 'check' : 'alert'} size={15} /><strong>{r.name}</strong><span class="muted small">{r.message}</span></li>{/each}
          </ul>
        {/if}
      {:else if step === 2}
        <h2>Your server</h2>
        <p class="muted">The host name is how mail servers and apps reach this machine. The mail domain is the part after @ in your addresses.</p>
        <div class="grid2">
          <label class="field"><span>Server host name</span><input class="input" bind:value={hostname} placeholder="mail.example.com" /></label>
          <label class="field"><span>Mail domain</span><input class="input" bind:value={domain} placeholder="example.com" /></label>
        </div>
        <p class="hint">You can add more domains later. Point the host name’s A/AAAA record at this server.</p>
      {:else if step === 3}
        <h2>How people sign in</h2>
        <p class="muted">Choose how administrators and mailbox users sign in to this web console. You can change this later.</p>
        <div class="choices">
          <button class="choice" class:on={method === 'password'} onclick={() => (method = 'password')}>
            <Icon name="key" size={20} /><strong>Email and password</strong><span>Accounts managed here.</span>
          </button>
          <button class="choice" class:on={method === 'oidc'} onclick={() => (method = 'oidc')}>
            <Icon name="lock" size={20} /><strong>Single sign-on</strong><span>OpenID Connect: Okta, Entra ID, Google, Keycloak…</span>
          </button>
        </div>
        {#if method === 'oidc'}
          <div class="redirect"><span class="small muted">Register this redirect URI with your identity provider</span><div class="row"><code>{info?.redirect_uri}</code><Copy value={info?.redirect_uri ?? ''} /></div></div>
          <div class="grid2">
            <label class="field"><span>Provider name</span><input class="input" bind:value={oidc.display_name} placeholder="Okta" /></label>
            <label class="field"><span>Issuer URL</span><input class="input mono" bind:value={oidc.issuer} placeholder="https://login.example.com" /></label>
            <label class="field"><span>Client ID</span><input class="input mono" bind:value={oidc.client_id} /></label>
            <label class="field"><span>Client secret</span><input class="input mono" type="password" bind:value={oidc.client_secret} autocomplete="off" /></label>
          </div>
          <div class="row"><button class="btn small" onclick={checkProvider} disabled={busy || !oidc.issuer}><Icon name="zap" size={15} /> Check provider</button></div>
          {#if oidcTest}
            {#if oidcTest.ok}<div class="notice"><Icon name="check" size={18} /><span>Found {oidcTest.issuer}.</span></div>
            {:else}<div class="notice danger"><Icon name="alert" size={18} /><span>{oidcTest.error}</span></div>{/if}
          {/if}
          <Toggle bind:checked={alsoPassword} label="Also allow email and password sign-in" hint="Off: everyone uses single sign-on. Break-glass: PICACHO_ALLOW_PASSWORD_LOGIN=1." />
        {/if}
        <Toggle bind:checked={mailPasswords} label="Allow account passwords in mail apps" hint="Off: IMAP, SMTP and JMAP need app passwords or OAuth." />
      {:else if step === 4}
        <h2>Outgoing mail</h2>
        <p class="muted">Many hosting providers block port 25. If yours does, or you want better deliverability, send through a relay service.</p>
        <div class="choices">
          <button class="choice" class:on={outbound === 'direct'} onclick={() => (outbound = 'direct')}>
            <Icon name="send" size={20} /><strong>Deliver directly</strong><span>Look up each recipient’s mail server and connect to it.</span>
          </button>
          <button class="choice" class:on={outbound === 'relay'} onclick={() => { outbound = 'relay'; if (!relay.host) applyPreset(preset); }}>
            <Icon name="route" size={20} /><strong>Use a relay</strong><span>Amazon SES, SendGrid, Mailgun, Postmark, your ISP or another server.</span>
          </button>
        </div>
        {#if outbound === 'relay'}
          <div class="presets">{#each RELAY_PRESETS as p}<button class="chip" class:accent={preset === p.id} onclick={() => applyPreset(p.id)}>{p.name}</button>{/each}</div>
          <div class="grid2">
            <label class="field"><span>Host</span><input class="input" bind:value={relay.host} placeholder="smtp.example.com" /></label>
            <label class="field"><span>Port</span><input class="input" type="number" bind:value={relay.port} /></label>
            <label class="field"><span>Security</span>
              <select class="input" bind:value={relay.tls}><option value="starttls">STARTTLS (587)</option><option value="tls">TLS (465)</option><option value="opportunistic">STARTTLS if offered</option><option value="none">None</option></select>
            </label>
            <label class="field"><span>Username</span><input class="input" bind:value={relay.username} autocomplete="off" /></label>
            <label class="field"><span>Password or API key</span><input class="input" type="password" bind:value={relay.password} autocomplete="off" /></label>
          </div>
        {/if}
      {:else if step === 5}
        <h2>Administrator</h2>
        <p class="muted">This is a real mailbox too. postmaster@ and abuse@ deliver here.</p>
        <label class="field"><span>Your name</span><input class="input" bind:value={adminName} placeholder="Alex Morgan" autocomplete="name" /></label>
        <label class="field"><span>Address</span><div class="addr"><input class="input" bind:value={adminLocal} autocomplete="username" /><span class="at">@{domain}</span></div></label>
        {#if method === 'password'}
          <div class="grid2">
            <label class="field"><span>Password</span>
              <div class="pw"><input class="input" type={showPw ? 'text' : 'password'} bind:value={password} autocomplete="new-password" /><button type="button" class="icon-btn" onclick={() => (showPw = !showPw)} aria-label="Show password"><Icon name="eye" size={16} /></button></div>
            </label>
            <label class="field"><span>Confirm password</span><input class="input" type={showPw ? 'text' : 'password'} bind:value={confirm} autocomplete="new-password" /></label>
          </div>
          <div class="strength"><div class="bars">{#each [1, 2, 3, 4] as i}<span class:on={strength >= i} data-level={strength}></span>{/each}</div><span class="hint">At least {info?.password_min_length ?? 10} characters; a long passphrase is best.</span></div>
        {:else}
          {#if !oidc.client_secret}<label class="field"><span>Client secret (re-enter if your provider needs one)</span><input class="input mono" type="password" bind:value={oidc.client_secret} /></label>{/if}
          <div class="notice"><Icon name="lock" size={18} /><span>You'll sign in with {oidc.display_name || 'your provider'}. That identity becomes the administrator of <strong>{adminLocal}@{domain}</strong>.</span></div>
        {/if}
        <dl class="review">
          <dt>Server</dt><dd>{hostname} · {domain}</dd>
          <dt>Sign-in</dt><dd>{method === 'oidc' ? `Single sign-on (${oidc.display_name || oidc.issuer})${alsoPassword ? ' and password' : ''}` : 'Email and password'}</dd>
          <dt>Outgoing</dt><dd>{outbound === 'direct' ? 'Direct delivery' : `Relay via ${relay.host}:${relay.port}`}</dd>
          {#if info?.storage}<dt>Storage</dt><dd>{info.storage.database} · {info.storage.messages}{info.storage.encrypted ? ' · encrypted' : ''}</dd>{/if}
        </dl>
      {:else}
        <div class="done-head"><span class="ok"><Icon name="check" size={22} stroke={2.4} /></span><h2>Your mail server is ready</h2></div>
        <p class="muted">Publish these DNS records for <strong>{domain}</strong>. The console checks them for you under Domains.</p>
        {#if records.length}
          <div class="records">{#each records as r}<div class="rec"><div class="rec-head"><span class="chip">{r.type}</span><span class="mono small">{r.name}</span></div><div class="rec-val"><code>{r.value}</code><Copy value={r.zone_value ?? r.value} /></div></div>{/each}</div>
        {/if}
        {#if client}
          <div class="section-title">Mail app settings</div>
          <div class="grid2 small">
            <div><strong>IMAP</strong><div class="muted">{client.imap.host} · port {client.imap.port} · {client.imap.security}</div></div>
            <div><strong>SMTP</strong><div class="muted">{client.smtp.host} · port {client.smtp.port} · {client.smtp.security}</div></div>
          </div>
        {/if}
        <div class="actions"><button class="btn primary big" onclick={() => onDone(me)}>Open the console</button></div>
      {/if}

      {#if step >= 1 && step <= 5 && !restarting}
        {#if error}<p class="error-text">{error}</p>{/if}
        <div class="actions">
          <button class="btn ghost" onclick={() => { error = ''; step -= 1; persist(); }} disabled={busy || step === 1}><Icon name="back" size={16} /> Back</button>
          <span class="spacer"></span>
          {#if step === 1}
            <button class="btn" onclick={testStorage} disabled={busy}>Test</button>
            <button class="btn primary big" onclick={saveStorage} disabled={busy}>{busy ? 'Saving…' : 'Continue'}</button>
          {:else if step < 5}
            <button class="btn primary big" onclick={next}>Continue</button>
          {:else if method === 'password'}
            <button class="btn primary big" onclick={finishPassword} disabled={busy}>{busy ? 'Creating…' : 'Create server'}</button>
          {:else}
            <button class="btn primary big" onclick={finishOidc} disabled={busy}><Icon name="lock" size={16} /> {busy ? 'Redirecting…' : `Create and sign in with ${oidc.display_name || 'SSO'}`}</button>
          {/if}
        </div>
      {/if}
    </section>
  </main>
</div>

<style>
  .setup { min-height: 100%; display: flex; flex-direction: column; }
  header { display: flex; align-items: center; justify-content: space-between; padding: 12px 18px; }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 17px; }
  main { flex: 1; display: flex; flex-direction: column; align-items: center; padding: 20px 16px 60px; gap: 22px; }
  .panel { width: min(660px, 100%); padding: 30px 32px; display: grid; gap: 16px; border-radius: 16px; box-shadow: var(--shadow); }
  h2 { font-size: 24px; font-weight: 600; }
  p { margin: 0; }
  form { display: grid; gap: 12px; }
  .key { height: 50px; font-size: 18px; letter-spacing: 0.06em; text-align: center; }
  .actions { display: flex; align-items: center; gap: 10px; margin-top: 8px; flex-wrap: wrap; }
  .actions .btn.big { min-width: 160px; justify-content: center; }
  .steps { display: flex; gap: 16px; list-style: none; padding: 0; margin: 0; flex-wrap: wrap; justify-content: center; }
  .steps li { display: flex; align-items: center; gap: 8px; color: var(--muted); font-size: 14px; }
  .steps li.current { color: var(--text); font-weight: 600; }
  .bullet { width: 24px; height: 24px; border-radius: 50%; display: grid; place-items: center; font-size: 12px; font-weight: 700; border: 1px solid var(--border); background: var(--raised); }
  .steps li.current .bullet { border-color: var(--accent); color: var(--accent); }
  .steps li.done .bullet { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
  .sub-block { display: grid; gap: 10px; padding: 14px; border: 1px solid var(--border); border-radius: 12px; background: var(--surface); }
  .label { font-size: 13px; font-weight: 600; color: var(--muted); }
  .addr { display: flex; align-items: center; gap: 8px; }
  .addr .input { flex: 1; }
  .at { color: var(--muted); white-space: nowrap; }
  .pw { position: relative; }
  .pw .icon-btn { position: absolute; right: 2px; top: 2px; }
  .strength { display: flex; align-items: center; gap: 12px; }
  .bars { display: flex; gap: 4px; }
  .bars span { width: 34px; height: 5px; border-radius: 4px; background: var(--border); }
  .bars span.on { background: var(--warning); }
  .bars span.on[data-level='3'], .bars span.on[data-level='4'] { background: var(--accent); }
  .bars span.on[data-level='1'] { background: var(--danger); }
  .choices { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .choice { display: grid; gap: 6px; text-align: left; padding: 16px; border-radius: 12px; border: 1px solid var(--border); background: var(--paper); cursor: pointer; color: var(--muted); }
  .choice strong { color: var(--text); font-size: 15px; }
  .choice span { font-size: 13.5px; }
  .choice.on { border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 20%, transparent); color: var(--accent); }
  .presets { display: flex; flex-wrap: wrap; gap: 8px; }
  .presets .chip { cursor: pointer; height: 28px; padding: 0 12px; font-size: 13px; }
  .redirect { display: grid; gap: 4px; padding: 10px 12px; border-radius: 10px; background: var(--surface); border: 1px solid var(--border); }
  .redirect code { word-break: break-all; font-size: 13px; }
  .tests { list-style: none; padding: 0; margin: 0; display: grid; gap: 6px; }
  .tests li { display: flex; gap: 8px; align-items: baseline; color: var(--accent); }
  .tests li.bad { color: var(--danger); }
  .tests li strong { color: var(--text); font-weight: 500; }
  .review { display: grid; grid-template-columns: 110px 1fr; gap: 6px 14px; margin: 0; padding-top: 8px; border-top: 1px solid var(--border); }
  .review dt { color: var(--muted); }
  .review dd { margin: 0; word-break: break-word; }
  .done-head { display: flex; align-items: center; gap: 12px; }
  .ok { width: 38px; height: 38px; border-radius: 50%; display: grid; place-items: center; background: var(--soft); color: var(--accent); }
  .center { display: grid; justify-items: center; gap: 10px; text-align: center; padding: 20px 0; }
  .records { display: grid; gap: 8px; }
  .rec { border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; background: var(--surface); display: grid; gap: 6px; }
  .rec-head { display: flex; align-items: center; gap: 10px; word-break: break-all; }
  .rec-val { display: flex; align-items: flex-start; gap: 6px; }
  .rec-val code { flex: 1; word-break: break-all; font-size: 12px; max-height: 64px; overflow: auto; }
  @media (max-width: 560px) {
    .panel { padding: 22px 18px; }
    .choices { grid-template-columns: 1fr; }
    .steps .label-text { display: none; }
    .review { grid-template-columns: 1fr; }
  }
</style>
