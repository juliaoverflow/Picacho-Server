class Toasts {
  items = $state([]);
  #id = 0;
  show(message, kind = 'ok') {
    const id = ++this.#id;
    this.items.push({ id, message, kind });
    setTimeout(() => this.dismiss(id), kind === 'error' ? 6000 : 3200);
  }
  dismiss(id) {
    this.items = this.items.filter((t) => t.id !== id);
  }
  ok(m) {
    this.show(m, 'ok');
  }
  error(m) {
    this.show(m?.message || String(m), 'error');
  }
}
export const toast = new Toasts();
