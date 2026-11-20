<script>
  // List, edit, activate and delete Sieve scripts for one account.
  // `base` is '/me' or '/admin/accounts/{id}'.
  import { onMount } from 'svelte';
  import { get, put, post, del } from './api.js';
  import { toast } from './toast.svelte.js';
  import { ago } from './format.js';
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';

  let { base } = $props();
  let scripts = $state([]);
  let loaded = $state(false);
  let editing = $state(null); // { name, content, isNew, active }
  let saving = $state(false);
  let confirmDelete = $state(null);

  const TEMPLATE = `require ["fileinto"];

# File newsletters into their own folder.
if header :contains "list-id" "" {
  fileinto "Newsletters";
}
`;

  async function load() {
    try {
      scripts = await get(`${base}/sieve`);
    } catch (e) {
      toast.error(e);
    } finally {
      loaded = true;
    }
  }
  onMount(load);

  const path = (name) => `${base}/sieve/${encodeURIComponent(name)}`;

  async function open(s) {
    try {
      const full = await get(path(s.name));
      editing = { name: full.name, content: full.content, active: full.active, isNew: false };
    } catch (e) {
      toast.error(e);
    }
  }
  function create() {
    const n = scripts.length ? `filters-${scripts.length + 1}` : 'filters';
    editing = { name: n, content: TEMPLATE, active: false, isNew: true };
  }

  async function save(activate = false) {
    saving = true;
    try {
      const r = await put(path(editing.name.trim()), { content: editing.content, activate });
      toast.ok(activate ? `${r.name} saved and turned on.` : `${r.name} saved.`);
      editing = null;
      load();
    } catch (e) {
      toast.error(e);
    } finally {
      saving = false;
    }
  }
  async function setActive(s, active) {
    try {
      await post(`${path(s.name)}/activate`, { active });
      toast.ok(active ? `${s.name} is now the active script.` : 'No script is active now.');
      load();
    } catch (e) {
      toast.error(e);
    }
  }
  async function remove() {
    try {
      await del(path(confirmDelete.name));
      toast.ok(`${confirmDelete.name} deleted.`);
      confirmDelete = null;
      load();
    } catch (e) {
      toast.error(e);
    }
  }
</script>

{#if scripts.length}
  <table class="table">
    <thead><tr><th>Script</th><th>Status</th><th>Changed</th><th></th></tr></thead>
    <tbody>
      {#each scripts as s (s.name)}
        <tr>
          <td><button class="link mono" onclick={() => open(s)}>{s.name}</button></td>
          <td>{#if s.active}<span class="chip accent">Active</span>{:else}<span class="chip">Off</span>{/if}</td>
          <td class="muted">{ago(s.updated_at)}</td>
          <td class="actions">
            <button class="btn small" onclick={() => open(s)}>Edit</button>
            {#if s.active}<button class="btn small" onclick={() => setActive(s, false)}>Turn off</button>
            {:else}<button class="btn small" onclick={() => setActive(s, true)}>Make active</button>{/if}
            <button class="icon-btn" onclick={() => (confirmDelete = s)} aria-label="Delete {s.name}" title="Delete"><Icon name="trash" size={16} /></button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
{:else if loaded}
  <p class="muted small">No filter scripts yet. Only one script runs at a time: the active one.</p>
{/if}
<div class="row" style="margin-top:12px"><button class="btn" onclick={create}><Icon name="plus" size={16} /> New script</button></div>

<Modal title={editing?.isNew ? 'New Sieve script' : `Edit ${editing?.name ?? ''}`} open={!!editing} width={760}
  onclose={() => (editing = null)}>
  {#if editing}
    <label class="field"><span>Name</span><input class="input mono" bind:value={editing.name} disabled={!editing.isNew} required /></label>
    <label class="field"><span>Script</span>
      <textarea class="input mono code" rows="16" spellcheck="false" bind:value={editing.content}></textarea>
      <span class="hint">RFC 5228 Sieve with fileinto, reject, vacation, imap4flags, body, variables and more. The server checks the script when you save.</span>
    </label>
  {/if}
  {#snippet footer()}
    <button class="btn" onclick={() => (editing = null)}>Cancel</button>
    <button class="btn" onclick={() => save(false)} disabled={saving}>Save</button>
    {#if !editing?.active}<button class="btn primary" onclick={() => save(true)} disabled={saving}>Save and make active</button>{/if}
  {/snippet}
</Modal>

<Modal title="Delete script?" open={!!confirmDelete} width={420} onclose={() => (confirmDelete = null)}>
  <p>Delete <strong class="mono">{confirmDelete?.name}</strong>?{confirmDelete?.active ? ' It is the active script, so no filters will run afterwards.' : ''}</p>
  {#snippet footer()}
    <button class="btn" onclick={() => (confirmDelete = null)}>Cancel</button>
    <button class="btn danger" onclick={remove}>Delete script</button>
  {/snippet}
</Modal>

<style>
  .actions { display: flex; gap: 6px; justify-content: flex-end; align-items: center; }
  .link { border: 0; background: none; padding: 0; color: var(--accent); cursor: pointer; }
  .code { min-height: 280px; line-height: 1.5; tab-size: 2; }
</style>
