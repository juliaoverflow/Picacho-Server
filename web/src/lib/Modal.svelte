<script>
  import Icon from './Icon.svelte';
  let { title, open = $bindable(false), width = 480, children, footer, onclose } = $props();
  let dialog = $state();
  $effect(() => {
    if (open && dialog && !dialog.open) dialog.showModal();
    if (!open && dialog?.open) dialog.close();
  });
</script>

<dialog bind:this={dialog} onclose={() => { open = false; onclose?.(); }} style="width:min({width}px, calc(100vw - 32px))"
  onclick={(e) => e.target === dialog && (open = false)}>
  {#if open}
    <div class="wrap fade-in">
      <header>
        <h2>{title}</h2>
        <button class="icon-btn" onclick={() => (open = false)} aria-label="Close"><Icon name="x" /></button>
      </header>
      <div class="body">{@render children?.()}</div>
      {#if footer}<footer>{@render footer()}</footer>{/if}
    </div>
  {/if}
</dialog>

<style>
  dialog { border: 1px solid var(--border); border-radius: 14px; padding: 0; background: var(--raised); color: var(--text); box-shadow: var(--shadow); max-height: calc(100vh - 48px); }
  dialog::backdrop { background: var(--overlay); }
  .wrap { display: flex; flex-direction: column; max-height: calc(100vh - 50px); }
  header { display: flex; align-items: center; justify-content: space-between; padding: 14px 14px 10px 20px; border-bottom: 1px solid var(--border); }
  h2 { font-size: 17px; }
  .body { padding: 18px 20px; overflow: auto; display: grid; gap: 14px; }
  footer { display: flex; justify-content: flex-end; gap: 10px; padding: 12px 20px 16px; border-top: 1px solid var(--border); }
</style>
