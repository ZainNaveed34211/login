// Single configuration point for the account frontend. Change URLs here
// only — do not scatter hostnames through app.js.
// Production values (confirmed by the owner):
//   API:      https://account-api.kluzar.com
//   Payments: https://payments.kluzar.com (plans, options and payments)
//   Login:    this site itself, https://accounts.kluzar.com
// For local development, edit API_BASE_URL to your local Worker URL
// (for example http://localhost:8787) before serving this page locally.
// Never put secrets, keys, or tokens in this file.
window.KLUZAR_CONFIG = {
  API_BASE_URL: 'https://account-api.kluzar.com',
  PAYMENTS_URL: 'https://payments.kluzar.com',
};
