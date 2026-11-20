import { get, put } from './api.js';
import { toast } from './toast.svelte.js';

/** Load live settings for editing; `save()` writes the whole document. */
export function liveSettings() {
  const st = $state({ data: null, meta: null, saving: false, dirty: false, original: '' });
  async function load() {
    const r = await get('/admin/settings');
    st.data = r.settings;
    st.meta = r;
    st.original = JSON.stringify(r.settings);
  }
  async function save(message = 'Settings saved.') {
    st.saving = true;
    try {
      const r = await put('/admin/settings', st.data);
      st.data = r.settings;
      st.original = JSON.stringify(r.settings);
      toast.ok(message);
      return true;
    } catch (e) {
      toast.error(e);
      return false;
    } finally {
      st.saving = false;
    }
  }
  load().catch((e) => toast.error(e));
  return {
    get data() { return st.data; },
    get meta() { return st.meta; },
    get saving() { return st.saving; },
    get dirty() { return st.data && JSON.stringify(st.data) !== st.original; },
    load,
    save,
    reset() { st.data = JSON.parse(st.original); },
  };
}
