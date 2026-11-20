<script>
  let { checked = $bindable(false), label = '', hint = '', disabled = false, onchange } = $props();
</script>

<label class="toggle" class:disabled>
  <span class="text">
    <span class="title">{label}</span>
    {#if hint}<span class="hint">{hint}</span>{/if}
  </span>
  <input type="checkbox" bind:checked {disabled} onchange={() => onchange?.(checked)} />
  <span class="track" aria-hidden="true"><span class="thumb"></span></span>
</label>

<style>
  .toggle { display: flex; align-items: center; gap: 14px; cursor: pointer; padding: 6px 0; }
  .toggle.disabled { opacity: 0.55; cursor: default; }
  .text { flex: 1; display: grid; gap: 2px; }
  .title { font-weight: 500; }
  input { position: absolute; opacity: 0; width: 0; height: 0; }
  .track { width: 40px; height: 24px; border-radius: 999px; background: var(--border); position: relative; transition: background 0.15s; flex: none; }
  .thumb { position: absolute; top: 3px; left: 3px; width: 18px; height: 18px; border-radius: 50%; background: #fff; box-shadow: 0 1px 2px rgba(0,0,0,0.25); transition: transform 0.15s; }
  input:checked + .track { background: var(--accent); }
  input:checked + .track .thumb { transform: translateX(16px); }
  input:focus-visible + .track { outline: 2px solid var(--accent); outline-offset: 2px; }
</style>
