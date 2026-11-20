<script>
  import { toast } from './toast.svelte.js';
  import Icon from './Icon.svelte';
</script>

<div class="toasts" aria-live="polite">
  {#each toast.items as t (t.id)}
    <div class="toast fade-in" class:error={t.kind === 'error'}>
      <Icon name={t.kind === 'error' ? 'alert' : 'check'} size={16} />
      <span>{t.message}</span>
    </div>
  {/each}
</div>

<style>
  .toasts { position: fixed; bottom: 18px; left: 50%; transform: translateX(-50%); display: grid; gap: 8px; z-index: 100; pointer-events: none; }
  .toast { display: flex; align-items: center; gap: 10px; padding: 10px 16px; border-radius: 10px; background: var(--text); color: var(--bg); box-shadow: var(--shadow); font-size: 14px; max-width: min(520px, calc(100vw - 32px)); }
  .toast.error { background: var(--danger); color: #fff; }
</style>
