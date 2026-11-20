<script>
  // Out-of-office auto-reply for one account. `base` is '/me' or '/admin/accounts/{id}'.
  import { onMount } from 'svelte';
  import { get, put } from './api.js';
  import { toast } from './toast.svelte.js';
  import Toggle from './Toggle.svelte';

  let { base } = $props();
  let v = $state(null);
  let original = $state('');
  let saving = $state(false);

  // Dates are stored as unix seconds; edit them as local calendar days.
  const toDay = (ts) => {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  };
  const fromDay = (s) => (s ? Math.floor(new Date(`${s}T00:00:00`).getTime() / 1000) : null);

  function fill(r) {
    v = { enabled: r.enabled, subject: r.subject ?? '', text_body: r.text_body ?? '', html_body: r.html_body ?? null, from: toDay(r.from_date), to: toDay(r.to_date ? r.to_date - 1 : null), days: r.days || 7 };
    original = JSON.stringify(v);
  }
  onMount(async () => {
    try {
      fill(await get(`${base}/vacation`));
    } catch (e) {
      toast.error(e);
    }
  });
  const dirty = $derived(v && JSON.stringify(v) !== original);

  async function save(e) {
    e?.preventDefault();
    if (v.enabled && !v.text_body.trim()) return toast.error('Write the reply people should get.');
    if (v.from && v.to && v.to < v.from) return toast.error('The last day is before the first day.');
    saving = true;
    try {
      // The reply stops at the start of the day after the last day.
      let to = null;
      if (v.to) {
        const d = new Date(`${v.to}T00:00:00`);
        d.setDate(d.getDate() + 1);
        to = Math.floor(d.getTime() / 1000);
      }
      const r = await put(`${base}/vacation`, {
        enabled: v.enabled, subject: v.subject, text_body: v.text_body, html_body: v.html_body,
        from_date: fromDay(v.from), to_date: to, days: Number(v.days) || 7,
      });
      fill(r);
      toast.ok(v.enabled ? 'Auto-reply is on.' : 'Auto-reply saved (off).');
    } catch (err) {
      toast.error(err);
    } finally {
      saving = false;
    }
  }
</script>

{#if v}
  <form onsubmit={save} class="vac">
    <Toggle bind:checked={v.enabled} label="Send an automatic reply" hint="Each sender gets it at most once per period. Mailing lists and automated mail are skipped." />
    <div class="grid2">
      <label class="field"><span>First day</span><input class="input" type="date" bind:value={v.from} /><span class="hint">Leave empty to start now.</span></label>
      <label class="field"><span>Last day</span><input class="input" type="date" bind:value={v.to} /><span class="hint">Leave empty to keep replying until turned off.</span></label>
    </div>
    <label class="field"><span>Subject</span><input class="input" bind:value={v.subject} placeholder="Out of office" /></label>
    <label class="field"><span>Message</span><textarea class="input" rows="5" bind:value={v.text_body} placeholder="I'm away until Monday and will reply when I'm back."></textarea></label>
    <label class="field" style="max-width:260px"><span>Reply to the same sender every (days)</span><input class="input" type="number" min="1" max="365" bind:value={v.days} /></label>
    <div class="row"><button class="btn primary" disabled={saving || !dirty}>{saving ? 'Saving…' : 'Save auto-reply'}</button></div>
  </form>
{/if}

<style>
  .vac { display: grid; gap: 14px; }
</style>
