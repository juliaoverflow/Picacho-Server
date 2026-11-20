<script>
  import { onMount } from 'svelte';
  import { get } from '../lib/api.js';
  import { liveSettings } from '../lib/settings.svelte.js';
  import Icon from '../lib/Icon.svelte';
  import Toggle from '../lib/Toggle.svelte';
  import SaveBar from '../lib/SaveBar.svelte';
  import ListField from '../lib/ListField.svelte';

  const s = liveSettings();
  const f = $derived(s.data?.filter);
  let bayes = $state(null);
  onMount(async () => (bayes = await get('/admin/filter/bayes').catch(() => null)));

  const FIELDS = ['subject', 'from', 'to', 'body', 'raw', 'Reply-To', 'List-Id', 'X-Mailer', 'Content-Type'];
  function addRule() {
    f.rules = [...f.rules, { name: '', field: 'subject', pattern: '', score: 3, enabled: true }];
  }
  function removeRule(i) {
    f.rules = f.rules.filter((_, j) => j !== i);
  }
  const bayesReady = $derived(bayes && f && bayes.spam_learned >= f.bayes_min_learns && bayes.ham_learned >= f.bayes_min_learns);
</script>

<div class="page"><div class="page-inner">
  <div class="page-head"><div><h1>Spam &amp; content filter</h1><p class="muted" style="margin:6px 0 0">Every check adds to a message's score. The thresholds decide what happens to it. Changes apply to the next message.</p></div></div>
  {#if f}
    <div class="card">
      <Toggle bind:checked={f.enabled} label="Filter incoming mail" hint="Turn off to deliver everything without scoring (block lists under Security still apply)." />
      <div class="grid2" style="margin-top:10px">
        <label class="field"><span>File in Junk at score</span><input class="input" type="number" step="0.5" bind:value={f.junk_score} disabled={!f.enabled} /><span class="hint">Adds X-Spam-Flag: YES.</span></label>
        <label class="field"><span>Reject during SMTP at score</span><input class="input" type="number" step="0.5" bind:value={f.reject_score} disabled={!f.enabled} /><span class="hint">The sending server gets a 550 error.</span></label>
      </div>
      <div style="margin-top:8px">
        <Toggle bind:checked={f.add_headers} label="Add X-Spam-Score and X-Spam-Report headers" disabled={!f.enabled} />
        <Toggle bind:checked={f.scan_outbound} label="Also scan mail sent by your users" hint="Catches compromised accounts sending spam." disabled={!f.enabled} />
      </div>
    </div>

    <div class="card">
      <div class="row"><h3>Learning filter (Bayes)</h3><span class="spacer"></span>
        {#if bayes}{#if !f.bayes}<span class="chip">Off</span>{:else if bayesReady}<span class="chip accent">Scoring</span>{:else}<span class="chip warning">Still learning</span>{/if}{/if}
      </div>
      <p class="sub">Learns from people moving mail into and out of Junk, across all accounts.</p>
      {#if bayes}
        <div class="stats">
          <div><strong>{bayes.spam_learned.toLocaleString()}</strong><span>Spam learned</span></div>
          <div><strong>{bayes.ham_learned.toLocaleString()}</strong><span>Good mail learned</span></div>
          <div><strong>{bayes.tokens.toLocaleString()}</strong><span>Tokens</span></div>
        </div>
      {/if}
      <Toggle bind:checked={f.bayes} label="Use the learning filter" />
      <div class="grid2" style="margin-top:10px">
        <label class="field"><span>Messages of each kind before it scores</span><input class="input" type="number" min="0" bind:value={f.bayes_min_learns} disabled={!f.bayes} /></label>
        <label class="field"><span>Score at full certainty</span><input class="input" type="number" step="0.5" min="0" bind:value={f.bayes_weight} disabled={!f.bayes} /><span class="hint">Scaled down as certainty falls toward 50%.</span></label>
      </div>
    </div>

    <div class="card">
      <h3>Block lists</h3>
      <p class="sub">Listed senders add to the score instead of being refused outright. Lists that refuse connections are under Security.</p>
      <div class="grid2">
        <ListField bind:value={f.dnsbl} label="IP block lists" placeholder="bl.spamcop.net" />
        <ListField bind:value={f.uribl} label="Link block lists" placeholder="dbl.spamhaus.org" hint="Checked against domains linked in the message." />
      </div>
      <label class="field" style="margin-top:12px;max-width:260px"><span>Score when the IP is listed</span><input class="input" type="number" step="0.5" bind:value={f.dnsbl_score} /></label>
    </div>

    <div class="card">
      <h3>Senders</h3>
      <div class="grid2" style="margin-top:8px">
        <ListField bind:value={f.allow_senders} label="Never spam" placeholder="partner.example&#10;ceo@example.com" rows={3} hint="Addresses or whole domains." />
        <ListField bind:value={f.block_senders} label="Always spam" placeholder="spammy.example" rows={3} hint="Addresses or whole domains." />
      </div>
    </div>

    <div class="card">
      <div class="row"><h3>Custom rules</h3><span class="spacer"></span><button class="btn small" onclick={addRule}><Icon name="plus" size={15} /> Add rule</button></div>
      <p class="sub">Case-insensitive regular expressions. A match adds the score (use a negative score to favor mail).</p>
      {#if f.rules.length}
        <table class="table rules">
          <thead><tr><th>On</th><th>Name</th><th>Look in</th><th>Pattern</th><th>Score</th><th></th></tr></thead>
          <tbody>
            {#each f.rules as r, i}
              <tr>
                <td><input type="checkbox" bind:checked={r.enabled} aria-label="Enabled" /></td>
                <td><input class="input" bind:value={r.name} placeholder="Crypto pitch" /></td>
                <td><input class="input" list="rule-fields" bind:value={r.field} /></td>
                <td><input class="input mono" bind:value={r.pattern} placeholder="bitcoin|wallet" /></td>
                <td><input class="input num" type="number" step="0.5" bind:value={r.score} /></td>
                <td><button class="icon-btn" onclick={() => removeRule(i)} aria-label="Remove rule"><Icon name="trash" size={16} /></button></td>
              </tr>
            {/each}
          </tbody>
        </table>
        <datalist id="rule-fields">{#each FIELDS as x}<option value={x}></option>{/each}</datalist>
      {:else}<p class="muted small">No custom rules.</p>{/if}
    </div>

    <div class="card">
      <h3>Attachments</h3>
      <ListField bind:value={f.blocked_extensions} label="Refuse attachments ending in" rows={2} hint="Without the dot. Archives are not unpacked." />
    </div>

    <div class="card">
      <h3>rspamd</h3>
      <Toggle checked={!!f.rspamd} label="Ask an rspamd server" hint="Its score is added to Picacho's own." onchange={(v) => (f.rspamd = v ? { url: 'http://127.0.0.1:11333', password: null, use_action: true, timeout_secs: 15 } : null)} />
      {#if f.rspamd}
        <div class="grid2" style="margin-top:10px">
          <label class="field"><span>URL</span><input class="input mono" bind:value={f.rspamd.url} /></label>
          <label class="field"><span>Password</span><input class="input" type="password" autocomplete="new-password" value={f.rspamd.password ?? ''} oninput={(e) => (f.rspamd.password = e.target.value || null)} placeholder="None" /></label>
          <label class="field"><span>Timeout (seconds)</span><input class="input" type="number" min="1" bind:value={f.rspamd.timeout_secs} /></label>
        </div>
        <Toggle bind:checked={f.rspamd.use_action} label="Follow rspamd's action" hint="Reject, greylist or mark as spam when rspamd says so." />
      {/if}
    </div>

    <div class="card">
      <h3>ClamAV</h3>
      <Toggle checked={!!f.clamav} label="Scan for viruses with clamd" hint="Infected messages are refused." onchange={(v) => (f.clamav = v ? { address: '127.0.0.1:3310', on_error: 'accept', timeout_secs: 30 } : null)} />
      {#if f.clamav}
        <div class="grid2" style="margin-top:10px">
          <label class="field"><span>Address</span><input class="input mono" bind:value={f.clamav.address} /><span class="hint">host:port or unix:/run/clamav/clamd.ctl</span></label>
          <label class="field"><span>When clamd can't be reached</span>
            <select class="input" bind:value={f.clamav.on_error}><option value="accept">Deliver anyway</option><option value="tempfail">Ask the sender to retry later</option></select>
          </label>
          <label class="field"><span>Timeout (seconds)</span><input class="input" type="number" min="1" bind:value={f.clamav.timeout_secs} /></label>
        </div>
      {/if}
    </div>

    <div class="card">
      <h3>Greylisting</h3>
      <Toggle bind:checked={f.greylist.enabled} label="Delay mail from new senders" hint="Real servers retry; most spam software doesn't. Adds a few minutes to first contact." />
      {#if f.greylist.enabled}
        <div class="grid2" style="margin-top:10px">
          <label class="field"><span>Delay (seconds)</span><input class="input" type="number" min="0" bind:value={f.greylist.delay_secs} /></label>
          <label class="field"><span>Forget unretried senders after (hours)</span><input class="input" type="number" min="1" bind:value={f.greylist.retry_window_hours} /></label>
          <label class="field"><span>Remember passed senders (days)</span><input class="input" type="number" min="1" bind:value={f.greylist.pass_days} /></label>
          <label class="field"><span>Only when the score is at least</span><input class="input" type="number" step="0.5" min="0" bind:value={f.greylist.min_score} /><span class="hint">0 greylists every new sender.</span></label>
        </div>
      {/if}
    </div>
    <SaveBar {s} />
  {/if}
</div></div>

<style>
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 12px; }
  .stats > div { display: grid; padding: 12px 14px; border-radius: 10px; background: var(--surface); }
  .stats strong { font-size: 20px; font-weight: 600; }
  .stats span { color: var(--muted); font-size: 13px; }
  .rules td { vertical-align: middle; padding: 6px; }
  .rules .num { width: 80px; }
</style>
