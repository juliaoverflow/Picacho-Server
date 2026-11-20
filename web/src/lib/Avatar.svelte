<script>
  import { initials } from './format.js';
  let { text = '', size = 40 } = $props();
  // Same soft pairs as the Picacho app's avatars.
  const PAIRS = [
    ['#dbe9e1', '#3b6b51'], ['#e1e5ef', '#52658b'], ['#eae1d9', '#8c674e'],
    ['#e7deed', '#7f6391'], ['#dae7ea', '#4d7884'],
  ];
  const hue = $derived([...(text || '')].reduce((a, c) => a + c.charCodeAt(0), 0) % PAIRS.length);
</script>

<div class="avatar" style="--a:{PAIRS[hue][0]};--b:{PAIRS[hue][1]};width:{size}px;height:{size}px;font-size:{size * 0.36}px">
  {initials(text)}
</div>

<style>
  .avatar {
    display: grid; place-items: center; border-radius: 50%; flex: none;
    background: var(--a); color: var(--b); font-weight: 600; letter-spacing: 0.02em;
  }
  :global([data-theme='dark']) .avatar { background: var(--surface); color: var(--accent); }
</style>
