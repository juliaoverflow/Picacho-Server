// Minimal history router: `router.path` is reactive; `go()` navigates.
class Router {
  path = $state(location.pathname);

  constructor() {
    addEventListener('popstate', () => (this.path = location.pathname));
  }

  go(path, { replace = false } = {}) {
    if (path === this.path) return;
    if (replace) history.replaceState(null, '', path);
    else history.pushState(null, '', path);
    this.path = path;
  }

  /** ['accounts', '3'] for /accounts/3 */
  get parts() {
    return this.path.split('/').filter(Boolean);
  }
}

export const router = new Router();

/** Intercept clicks on internal links. */
export function link(node) {
  const onclick = (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey) return;
    const href = node.getAttribute('href');
    if (!href || !href.startsWith('/')) return;
    e.preventDefault();
    router.go(href);
  };
  node.addEventListener('click', onclick);
  return { destroy: () => node.removeEventListener('click', onclick) };
}
