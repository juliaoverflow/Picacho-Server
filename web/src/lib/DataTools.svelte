<script>
  // Export a mailbox, import an archive (admin), and copy mail from another IMAP server.
  // `base` is '/me' or '/admin/accounts/{id}'.
  import { onDestroy } from 'svelte';
  import { get, post, ApiError } from './api.js';
  import { toast } from './toast.svelte.js';
  import Icon from './Icon.svelte';

  let { base, canImport = false, label = 'this mailbox' } = $props();

  // ---- import
  let file = $state(null);
  let folder = $state('Imported');
  let importing = $state(false);
  let imported = $state(null);

  async function runImport(e) {
    e.preventDefault();
    if (!file) return;
    importing = true;
    imported = null;
    try {
      const res = await fetch(`/api${base}/import?folder=${encodeURIComponent(folder || 'Imported')}`, {
        method: 'POST',
        headers: { 'X-Picacho': '1', 'Content-Type': 'application/octet-stream', Accept: 'application/json' },
        body: file,
        credentials: 'same-origin',
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) throw new ApiError(res.status, data?.error || `Import failed (${res.status})`);
      imported = data;
      toast.ok(`Imported ${data.messages} message${data.messages === 1 ? '' : 's'}.`);
    } catch (err) {
      toast.error(err);
    } finally {
      importing = false;
    }
  }

  // ---- IMAP migration
  let m = $state({ host: '', port: '', security: 'tls', username: '', password: '', folders: '', prefix: '' });
  let job = $state(null);
  let timer;
  onDestroy(() => clearTimeout(timer));

  async function poll(id) {
    try {
      job = await get(`/admin/migrations/${id}`);
      if (job.state === 'running') timer = setTimeout(() => poll(id), 1500);
      else if (job.state === 'done') toast.ok(`Copied ${job.stats.messages} message${job.stats.messages === 1 ? '' : 's'}.`);
      else toast.error(job.error || 'The copy failed.');
    } catch (e) {
      toast.error(e);
    }
  }
  async function migrate(e) {
    e.preventDefault();
    try {
      const r = await post(`${base}/migrate`, {
        host: m.host.trim(),
        port: m.port ? Number(m.port) : null,
        security: m.security,
        username: m.username.trim(),
        password: m.password,
        folders: m.folders.split(/\n|,/).map((x) => x.trim()).filter(Boolean),
        prefix: m.prefix,
      });
      m.password = '';
      job = { state: 'running', done: 0, total: 0, folder: '', stats: { messages: 0, skipped: 0, folders: 0, errors: [] } };
      poll(r.id);
    } catch (err) {
      toast.error(err);
    }
  }
  const pct = $derived(job?.total ? Math.min(100, (job.done / job.total) * 100) : 0);
</script>

<div class="tools">
  <section>
    <h4>Export</h4>
    <p class="sub">Download {label} as a .zip: every folder as .eml files with flags, Sieve scripts, calendars and contacts.</p>
    <a class="btn" href="/api{base}/export" download><Icon name="download" size={16} /> Download export</a>
  </section>

  {#if canImport}
    <section>
      <h4>Import</h4>
      <p class="sub">Upload a Picacho export or a zipped Maildir (.zip), or an mbox file. Messages already in the mailbox are skipped.</p>
      <form class="row" onsubmit={runImport}>
        <input class="input file" type="file" accept=".zip,.mbox,.mbx,application/zip,application/mbox" onchange={(e) => (file = e.target.files[0] ?? null)} />
        <input class="input" style="max-width:180px" bind:value={folder} placeholder="Imported" title="Folder for mbox messages" aria-label="Folder for mbox messages" />
        <button class="btn" disabled={!file || importing}><Icon name="upload" size={16} /> {importing ? 'Importing…' : 'Import'}</button>
      </form>
      {#if imported}
        <p class="small result">{imported.messages} messages, {imported.folders} folders, {imported.scripts} scripts, {imported.dav} calendar/contact items · {imported.skipped} skipped</p>
        {#each imported.errors ?? [] as er}<p class="error-text">{er}</p>{/each}
      {/if}
    </section>
  {/if}

  <section>
    <h4>Copy from another server</h4>
    <p class="sub">Copies every folder over IMAP. It runs in the background; messages already copied are skipped if you run it again.</p>
    <form onsubmit={migrate} class="mig">
      <div class="grid3">
        <label class="field"><span>IMAP server</span><input class="input" bind:value={m.host} placeholder="imap.example.com" required /></label>
        <label class="field"><span>Security</span>
          <select class="input" bind:value={m.security}><option value="tls">TLS (993)</option><option value="starttls">STARTTLS (143)</option><option value="none">None (143)</option></select>
        </label>
        <label class="field"><span>Port</span><input class="input" type="number" min="1" max="65535" bind:value={m.port} placeholder="Default" /></label>
      </div>
      <div class="grid2">
        <label class="field"><span>User name</span><input class="input" bind:value={m.username} autocomplete="off" required /></label>
        <label class="field"><span>Password</span><input class="input" type="password" bind:value={m.password} autocomplete="new-password" required /><span class="hint">Used for this copy only; it isn't stored.</span></label>
        <label class="field"><span>Only these folders</span><input class="input" bind:value={m.folders} placeholder="All folders" /><span class="hint">Comma-separated, e.g. INBOX, Sent</span></label>
        <label class="field"><span>Put them under</span><input class="input" bind:value={m.prefix} placeholder="Keep folder names" /><span class="hint">e.g. "Old mail" puts INBOX in Old mail/INBOX</span></label>
      </div>
      <div class="row"><button class="btn" disabled={job?.state === 'running'}><Icon name="download" size={16} /> Start copying</button></div>
    </form>
    {#if job}
      <div class="job">
        <div class="row small">
          <strong>{job.state === 'running' ? 'Copying…' : job.state === 'done' ? 'Finished' : 'Failed'}</strong>
          {#if job.folder}<span class="muted">{job.folder}</span>{/if}
          <span class="spacer"></span>
          <span class="muted">{job.stats.messages} copied · {job.stats.skipped} skipped{job.total ? ` · ${job.done}/${job.total}` : ''}</span>
        </div>
        <div class="meter" class:full={job.state === 'failed'}><div style="width:{job.state === 'done' ? 100 : pct}%"></div></div>
        {#if job.error}<p class="error-text">{job.error}</p>{/if}
        {#each job.stats.errors ?? [] as er}<p class="error-text">{er}</p>{/each}
      </div>
    {/if}
  </section>
</div>

<style>
  .tools { display: grid; gap: 22px; }
  h4 { margin: 0 0 4px; font-size: 14px; }
  .sub { color: var(--muted); font-size: 13.5px; margin: 0 0 10px; }
  .file { padding: 6px 10px; max-width: 320px; }
  .mig { display: grid; gap: 14px; }
  .grid3 { display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 14px; }
  @media (max-width: 640px) { .grid3 { grid-template-columns: 1fr; } }
  .job { display: grid; gap: 8px; margin-top: 14px; padding: 12px 14px; border-radius: 10px; background: var(--surface); }
  .result { margin: 10px 0 0; }
</style>
