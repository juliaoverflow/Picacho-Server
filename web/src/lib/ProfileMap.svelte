<script>
  // Contact field -> claim (or LDAP attribute) mappings for the contact directory.
  import Icon from './Icon.svelte';

  let { map = $bindable([]), kind = 'claim', placeholder = '' } = $props();
  const FIELDS = [['phone', 'Phone'], ['given_name', 'Given name'], ['family_name', 'Family name'], ['nickname', 'Nickname'], ['photo', 'Photo URL'], ['address', 'Address'], ['website', 'Website'], ['birthday', 'Birthday'], ['organization', 'Organization'], ['title', 'Title'], ['department', 'Department']];

  function add() {
    const used = new Set(map.map((m) => m.field));
    map = [...map, { field: (FIELDS.find(([f]) => !used.has(f)) ?? FIELDS[0])[0], claim: '' }];
  }
</script>

<div class="map">
  {#each map as m, i}
    <select class="input" bind:value={m.field} aria-label="Contact field">
      {#each FIELDS as [f, label]}<option value={f}>{label}</option>{/each}
    </select>
    <input class="input mono" bind:value={m.claim} placeholder={placeholder} aria-label="{kind} for {m.field}" />
    <button type="button" class="icon-btn" onclick={() => (map = map.filter((_, j) => j !== i))} aria-label="Remove" title="Remove"><Icon name="trash" size={16} /></button>
  {/each}
</div>
<button type="button" class="btn small" onclick={add}><Icon name="plus" size={14} /> Add field</button>

<style>
  .map { display: grid; grid-template-columns: 160px minmax(0, 1fr) auto; gap: 6px 8px; align-items: center; margin: 6px 0 8px; }
</style>
