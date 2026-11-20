// Appearance preferences, kept per browser (a convenience, never required).
const read = (k, d) => {
  try {
    return localStorage.getItem(k) ?? d;
  } catch {
    return d;
  }
};
const write = (k, v) => {
  try {
    localStorage.setItem(k, v);
  } catch {
    /* private mode */
  }
};

export const ACCENTS = [
  ['green', '#246846', '#86cfaa'],
  ['teal', '#0b6b70', '#7fd0d0'],
  ['blue', '#2459a8', '#93b8f0'],
  ['purple', '#6741a8', '#bea5ef'],
  ['pink', '#a8336b', '#f0a3c6'],
  ['orange', '#a64a12', '#f2b07f'],
  ['graphite', '#444c59', '#c2c9d4'],
];

class Theme {
  appearance = $state(read('pm.appearance', 'system'));
  accent = $state(read('pm.accent', 'green'));
  systemDark = $state(matchMedia('(prefers-color-scheme: dark)').matches);
  dark = $derived(this.appearance === 'dark' || (this.appearance === 'system' && this.systemDark));

  constructor() {
    matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => (this.systemDark = e.matches));
    $effect.root(() => {
      $effect(() => {
        document.documentElement.dataset.theme = this.dark ? 'dark' : 'light';
        document.documentElement.dataset.accent = this.accent;
      });
    });
  }

  setAppearance(v) {
    this.appearance = v;
    write('pm.appearance', v);
  }
  setAccent(v) {
    this.accent = v;
    write('pm.accent', v);
  }
  toggle() {
    this.setAppearance(this.dark ? 'light' : 'dark');
  }
}

export const theme = new Theme();
