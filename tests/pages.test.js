import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const root = path.dirname(fileURLToPath(import.meta.url))
const PAGES = [
  'login-email', 'login-password', 'signup', 'mfa-setup', 'mfa-verify',
  'recovery-codes', 'forgot', 'forgot-reset', 'dashboard', 'profile',
  'password-change', 'mfa-manage', 'sessions', 'recovery-regenerate', 'expired',
]

test('every account state has its own separate page (refresh stays on that page)', () => {
  for (const page of PAGES) {
    const file = path.join(root, `../pages/${page}.html`)
    assert.ok(existsSync(file), `missing page: ${page}.html`)
    const html = readFileSync(file, 'utf8')
    assert.ok(html.includes(`data-page="${page}"`), `${page} must set data-page`)
    assert.ok(html.includes('../shared.js'), `${page} must load shared.js`)
    assert.ok(html.includes('global-error'), `${page} must have an error area`)
  }
  const index = readFileSync(path.join(root, '../index.html'), 'utf8')
  assert.ok(index.includes('pages/login-email.html'), 'root index must redirect to the email page')
})

test('separate pages: temporary tokens use sessionStorage only, never localStorage, never URLs, never passwords', () => {
  const shared = readFileSync(path.join(root, '../shared.js'), 'utf8')
  assert.ok(shared.includes('kluzar_setup_token'), 'setup token must be stored for page-to-page flow')
  assert.ok(shared.includes('kluzar_challenge_token'), 'challenge token must be stored for page-to-page flow')
  assert.ok(shared.includes('kluzar_recovery_token'), 'recovery token must be stored for page-to-page flow')
  assert.ok(shared.includes('sessionStorage'), 'temporary state must use sessionStorage')
  assert.ok(!shared.includes('localStorage.setItem') && !shared.includes('window.localStorage'), 'no persistent localStorage use for auth state')
  // Passwords must never be written to storage. The only password-related
  // sessionStorage key allowed is the failure COUNTER, not a password.
  assert.ok(!shared.includes("setItem('kluzar_password'"), 'passwords must never be stored')
  assert.ok(shared.includes('kluzar_password_failures'), 'failure counter key must exist')
  // Tokens must never be put into a URL query string.
  assert.ok(!shared.includes('?setupToken=') && !shared.includes('?challengeToken=') && !shared.includes('?recoveryToken='))
})

test('separate pages: forgot flow is two pages, not one combined form', () => {
  const forgot = readFileSync(path.join(root, '../pages/forgot.html'), 'utf8')
  const reset = readFileSync(path.join(root, '../pages/forgot-reset.html'), 'utf8')
  assert.ok(forgot.includes('form-forgot'), 'forgot page must have the code-check form')
  assert.ok(!forgot.includes('form-reset'), 'forgot page must NOT contain the new-password form')
  assert.ok(reset.includes('form-reset'), 'reset page must have the new-password form')
  assert.ok(!reset.includes('form-forgot'), 'reset page must NOT contain the code-check form')
})
