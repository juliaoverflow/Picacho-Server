<script>
  // A textarea bound to a string array: one entry per line (commas and spaces also split).
  let { value = $bindable([]), label, hint = '', placeholder = '', rows = 2 } = $props();
  let text = $state('');
  $effect(() => {
    text = (value ?? []).join('\n');
  });
  function commit() {
    value = text.split(/[\n,\s]+/).map((x) => x.trim()).filter(Boolean);
  }
</script>

<label class="field">
  <span>{label}</span>
  <textarea class="input mono" {rows} {placeholder} bind:value={text} onchange={commit}></textarea>
  {#if hint}<span class="hint">{hint}</span>{/if}
</label>
