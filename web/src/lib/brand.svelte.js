// Branding chosen by the administrator (name, logo, accent, sign-in text).
export const brand = $state({
  name: 'Picacho Server',
  logo: null,
  accent: null,
  login_message: null,
  support_url: null,
  support_email: null,
  hide_powered_by: false,
});

function luminance(hex) {
  const n = parseInt(hex.slice(1), 16);
  const c = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => {
    v /= 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}

export function applyBranding(b) {
  const next = { ...b, name: b?.name?.trim() || 'Picacho Server' };
  Object.assign(brand, next);
  document.title = brand.name;
  let el = document.getElementById('brand-accent');
  if (!el) {
    el = document.createElement('style');
    el.id = 'brand-accent';
    document.head.appendChild(el);
  }
  const a = brand.accent;
  if (a && /^#[0-9a-f]{6}$/i.test(a)) {
    const onLight = luminance(a) > 0.35 ? '#13291e' : '#ffffff';
    el.textContent = `
      :root:root { --accent: ${a}; --accent-hover: color-mix(in srgb, ${a} 86%, white); --on-accent: ${onLight};
        --soft: color-mix(in srgb, ${a} 16%, var(--surface)); }
      :root:root[data-theme='dark'] { --accent: color-mix(in srgb, ${a} 62%, white); --accent-hover: color-mix(in srgb, ${a} 50%, white);
        --on-accent: #10161c; --soft: color-mix(in srgb, ${a} 28%, var(--surface)); }`;
  } else {
    el.textContent = '';
  }
  let icon = document.querySelector('link[rel="icon"]');
  if (icon) icon.href = brand.logo || '/favicon.svg';
}
