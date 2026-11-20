// Cross-page UI state.
class Ui {
  /** Incremented to ask the current page to open its "new" dialog. */
  create = $state({ kind: '', n: 0 });
  sidebarCollapsed = $state(false);
  me = $state(null);
  status = $state(null);
  restartRequired = $state(false);
  restarting = $state(false);
  paletteOpen = $state(false);

  requestCreate(kind) {
    this.create = { kind, n: this.create.n + 1 };
  }
}
export const ui = new Ui();

/** Run `fn` when the sidebar's "New …" button asks for `kind`. Call during component init. */
export function onCreate(kind, fn) {
  let seen = ui.create.n;
  $effect(() => {
    const c = ui.create;
    if (c.n > seen) {
      seen = c.n;
      if (c.kind === kind) fn();
    }
  });
}

/** Restart the server and reload once it's back. */
export async function restartServer(post) {
  ui.restarting = true;
  try {
    await post('/admin/restart');
  } catch (e) {
    ui.restarting = false;
    throw e;
  }
  const started = Date.now();
  await new Promise((r) => setTimeout(r, 1200));
  while (Date.now() - started < 60000) {
    try {
      const r = await fetch('/api/status', { cache: 'no-store' });
      if (r.ok) {
        location.reload();
        return;
      }
    } catch {
      /* still restarting */
    }
    await new Promise((r) => setTimeout(r, 800));
  }
  ui.restarting = false;
  throw new Error('The server did not come back within a minute. Check its logs.');
}
