// Common outbound relays. Hosts and ports from each provider's SMTP docs.
export const RELAY_PRESETS = [
  { id: 'ses', name: 'Amazon SES', host: 'email-smtp.us-east-1.amazonaws.com', port: 587, tls: 'starttls' },
  { id: 'sendgrid', name: 'SendGrid', host: 'smtp.sendgrid.net', port: 587, tls: 'starttls', username: 'apikey' },
  { id: 'mailgun', name: 'Mailgun', host: 'smtp.mailgun.org', port: 587, tls: 'starttls' },
  { id: 'postmark', name: 'Postmark', host: 'smtp.postmarkapp.com', port: 587, tls: 'starttls' },
  { id: 'resend', name: 'Resend', host: 'smtp.resend.com', port: 465, tls: 'tls', username: 'resend' },
  { id: 'brevo', name: 'Brevo', host: 'smtp-relay.brevo.com', port: 587, tls: 'starttls' },
  { id: 'gmail', name: 'Google Workspace', host: 'smtp-relay.gmail.com', port: 587, tls: 'starttls' },
  // Saved as a `cloudflare` transport, which trims headers Cloudflare refuses.
  { id: 'cloudflare', kind: 'cloudflare', name: 'Cloudflare', host: 'smtp.mx.cloudflare.net', port: 465, tls: 'tls', username: 'api_token' },
  { id: 'custom', name: 'Other', host: '', port: 587, tls: 'starttls' },
];
