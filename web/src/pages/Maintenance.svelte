<script>
  import { post } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import { toast } from '../lib/toast.svelte.js';
  import { link } from '../lib/router.svelte.js';
  import Icon from '../lib/Icon.svelte';
  import SaveBar from '../lib/SaveBar.svelte';

  const s = liveSettings();
  const r = $derived(s.data?.retention);
  let busy = $state('');
  let last = $state({});

  const SPECIAL = ['\\Sent', '\\Archive', '\\Drafts', '\\Trash', '\\Junk'];
  function addRule() {
    r.rules = [...r.rules, { folder: '\\Sent', days: 365 }];
  }
  function removeRule(i) {
    r.rules = r.rules.filter((_, j) => j !== i);
  }

  const TASKS = [
    ['retention', 'Apply retention now', 'Deletes old Trash, Junk and rule-matched messages using the saved settings. Runs daily on its own.', 'trash',
      (x) => `Removed ${x.removed} message${x.removed === 1 ? '' : 's'}.`],
    ['sweep', 'Sweep unused storage', 'Removes stored messages, attachments and files nothing refers to any more, once they are older than the grace period.', 'database',
      (x) => `Removed ${x.removed} mail object${x.removed === 1 ? '' : 's'} and ${x.removed_dav} file${x.removed_dav === 1 ? '' : 's'}.`],
    ['reports', 'Send DMARC and TLS reports', 'Sends the reports that are switched on under Reports for the last day.', 'send', () => 'Reports sent.'],
  ];
  async function run(task, msg) {
    busy = task;
    try {
      const x = await post(`/admin/maintenance/${task}`);
      last[task] = msg(x);
      toast.ok(msg(x));
    } catch (e) {
      toast.error(e);
    } finally {
      busy = '';
    }
  }
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>Retention &amp; maintenance</h1><p class="muted" style="margin:6px 0 0">Automatic clean-up of old mail and logs, and jobs you can run now.</p></div></div>
  {#if r}
    <div class="card">
      <h3>Keep mail</h3>
      <p class="sub">Applies to every account. 0 keeps messages forever.</p>
      <div class="grid2">
        <label class="field"><span>Empty Trash after (days)</span><input class="input" type="number" min="0" bind:value={r.trash_days} /></label>
        <label class="field"><span>Empty Junk after (days)</span><input class="input" type="number" min="0" bind:value={r.junk_days} /></label>
      </div>
      <div class="row" style="margin-top:16px"><strong class="small">Other folders</strong><span class="spacer"></span><button class="btn small" onclick={addRule}><Icon name="plus" size={15} /> Add folder</button></div>
      {#if r.rules.length}
        <table class="table rules" style="margin-top:6px">
          <thead><tr><th>Folder</th><th>Delete after (days)</th><th></th></tr></thead>
          <tbody>
            {#each r.rules as rule, i}
              <tr>
                <td><input class="input mono" list="special-use" bind:value={rule.folder} placeholder="Archive/2019 or \Sent" /></td>
                <td><input class="input" type="number" min="1" bind:value={rule.days} style="max-width:140px" /></td>
                <td><button class="icon-btn" onclick={() => removeRule(i)} aria-label="Remove"><Icon name="trash" size={16} /></button></td>
              </tr>
            {/each}
          </tbody>
        </table>
        <datalist id="special-use">{#each SPECIAL as x}<option value={x}></option>{/each}</datalist>
        <p class="hint" style="margin:8px 0 0">Use a folder name, or a special use like <span class="mono">\Sent</span> to match it in every language.</p>
      {:else}<p class="muted small" style="margin:6px 0 0">No per-folder rules.</p>{/if}
    </div>
    <div class="card">
      <h3>Keep records</h3>
      <div class="grid2" style="margin-top:8px">
        <label class="field"><span>Audit log (days)</span><input class="input" type="number" min="1" bind:value={r.audit_days} /><span class="hint"><a href="/audit" use:link>View the audit log</a></span></label>
        <label class="field"><span>Grace period for unused storage (hours)</span><input class="input" type="number" min="1" bind:value={r.orphan_grace_hours} /><span class="hint">Protects objects still being written or restored.</span></label>
      </div>
    </div>
    <SaveBar {s} />
  {/if}

  <div class="section-title">Run now</div>
  {#each TASKS as [task, title, desc, icon, msg]}
    <div class="card row task">
      <Icon name={icon} />
      <div style="flex:1;min-width:220px"><h3>{title}</h3><p class="sub" style="margin:0">{desc}</p>{#if last[task]}<p class="small" style="margin:6px 0 0"><Icon name="check" size={14} /> {last[task]}</p>{/if}</div>
      <button class="btn" onclick={() => run(task, msg)} disabled={!!busy || (task === 'retention' && s.dirty)} title={task === 'retention' && s.dirty ? 'Save your changes first' : ''}>{busy === task ? 'Running…' : 'Run'}</button>
    </div>
  {/each}

  <div class="card row">
    <div style="flex:1"><h3>Backups and moving accounts</h3><p class="sub" style="margin:0">Export, import or copy a mailbox from another server on its account page.</p></div>
    <a class="btn" href="/accounts" use:link>Open Accounts</a>
  </div>
</div></div>

<style>
  .rules td { vertical-align: middle; padding: 6px; }
  .task :global(svg) { color: var(--muted); flex: none; }
</style>
