<script>
  import Icon from './Icon.svelte';
  let { value, label = 'Copy' } = $props();
  let done = $state(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      done = true;
      setTimeout(() => (done = false), 1400);
    } catch {
      /* clipboard unavailable */
    }
  }
</script>

<button class="icon-btn copy" onclick={copy} title={label} aria-label={label}>
  <Icon name={done ? 'check' : 'copy'} size={16} />
</button>

<style>
  .copy { width: 28px; height: 28px; }
</style>
