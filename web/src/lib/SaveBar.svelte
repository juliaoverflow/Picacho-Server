<script>
  let { s } = $props();
</script>

{#if s.dirty}
  <div class="savebar fade-in">
    <span>You have unsaved changes.</span>
    <span class="spacer"></span>
    <button class="btn small" onclick={() => s.reset()}>Discard</button>
    <button class="btn primary small" onclick={() => s.save()} disabled={s.saving}>{s.saving ? 'Saving…' : 'Save changes'}</button>
  </div>
{/if}

<style>
  .savebar { position: sticky; bottom: 16px; margin-top: 18px; display: flex; align-items: center; gap: 10px; padding: 10px 12px 10px 18px; border-radius: 12px; background: var(--raised); border: 1px solid var(--border); box-shadow: var(--shadow); }
</style>
