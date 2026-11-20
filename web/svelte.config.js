export default {
  // Autofocus is used deliberately in dialogs and the first setup field.
  onwarn: (w, handler) => w.code !== 'a11y_autofocus' && handler(w),
};
