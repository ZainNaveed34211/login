import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const root = path.dirname(fileURLToPath(import.meta.url))
// Clean paths: folder -> data-page. Every URL is a folder path, never
// a .html file. Spelling is fixed: forget-password (not forgot-password,
// not forgot.html).
const PAGES = [
  ['login', 'login-email'],
  ['login/password', 'login-password'],
  ['signup', 'signup'],
  ['mfa-setup', 'mfa-setup'],
  ['login/code', 'mfa-verify'],
  ['recovery-codes', 'recovery-codes'],
  ['forget-password', 'forget-password'],
  ['forget-password/reset', 'forget-password-reset'],
  ['dashboard', 'dashboard'],
  ['profile', 'profile'],
  ['change-password', 'password-change'],
  ['authenticator', 'authenticator'],
  ['sessions', 'sessions'],
  ['recovery-codes/regenerate', 'recovery-regenerate'],
  ['expired', 'expired'],
]

test('every account state has its own clean path (folder/index.html, refresh stays on that path)', () => {
  for (const [folder, datapage] of PAGES) {
    const file = path.join(root, `../${folder}/index.html`)
    assert.ok(existsSync(file), `missing page: ${folder}/index.html`)
    const html = readFileSync(file, 'utf8')
    assert.ok(html.includes(`data-page="${datapage}"`), `${folder} must set data-page="${datapage}"`)
    assert.ok(html.includes('/shared.js'), `${folder} must load shared.js`)
    assert.ok(html.includes('global-error'), `${folder} must have an error area`)
  }
  const index = readFileSync(path.join(root, '../index.html'), 'utf8')
  assert.ok(index.includes('/login/'), 'root index must redirect to /login/')
  assert.ok(!index.includes('.html'), 'root index must not link to a .html URL')
})

test('clean URLs: navigation uses folder paths only, never .html, and forget-password spelling is correct', () => {
  const shared = readFileSync(path.join(root, '../shared.js'), 'utf8')
  assert.ok(!shared.includes('.html'), 'shared navigation must not contain any .html URL')
  assert.ok(shared.includes("'/forget-password/'"), 'forget-password path must be used')
  assert.ok(!shared.includes('forgot.html') && !shared.includes('forgot-password'), 'old forgot spelling must not remain in navigation')
  for (const [folder] of PAGES) {
    const html = readFileSync(path.join(root, `../${folder}/index.html`), 'utf8')
    assert.ok(!html.includes('.html"'), `${folder} must not link to a .html file`)
  }
})

test('separate pages: temporary tokens use sessionStorage only, never localStorage, never URLs, never passwords', () => {
  const shared = readFileSync(path.join(root, '../shared.js'), 'utf8')
  assert.ok(shared.includes('kluzar_setup_token'), 'setup token must be stored for page-to-page flow')
  assert.ok(shared.includes('kluzar_challenge_token'), 'challenge token must be stored for page-to-page flow')
  assert.ok(shared.includes('kluzar_recovery_token'), 'recovery token must be stored for page-to-page flow')
  assert.ok(shared.includes('sessionStorage'), 'temporary state must use sessionStorage')
  assert.ok(!shared.includes('localStorage.setItem') && !shared.includes('window.localStorage'), 'no persistent localStorage use for auth state')
  assert.ok(!shared.includes("setItem('kluzar_password'"), 'passwords must never be stored')
  assert.ok(shared.includes('kluzar_password_failures'), 'failure counter key must exist')
  assert.ok(!shared.includes('?setupToken=') && !shared.includes('?challengeToken=') && !shared.includes('?recoveryToken='))
})

test('separate pages: forget-password flow is two pages, not one combined form', () => {
  const forgot = readFileSync(path.join(root, '../forget-password/index.html'), 'utf8')
  const reset = readFileSync(path.join(root, '../forget-password/reset/index.html'), 'utf8')
  assert.ok(forgot.includes('form-forgot'), 'forget-password page must have the code-check form')
  assert.ok(!forgot.includes('form-reset'), 'forget-password page must NOT contain the new-password form')
  assert.ok(reset.includes('form-reset'), 'reset page must have the new-password form')
  assert.ok(!reset.includes('form-forgot'), 'reset page must NOT contain the code-check form')
})

test('no third-party URLs in the accounts frontend: fonts are system fonts, QR library is bundled locally', () => {
  const styles = readFileSync(path.join(root, '../styles.css'), 'utf8')
  assert.ok(!styles.includes('fonts.googleapis') && !styles.includes('@import'), 'no Google Fonts or @import in styles')
  assert.ok(styles.includes('system-ui'), 'fonts must be system fonts')
  const shared = readFileSync(path.join(root, '../shared.js'), 'utf8')
  assert.ok(!shared.includes('fonts.googleapis') && !shared.includes('cdn.') && !shared.includes('unpkg') && !shared.includes('jsdelivr'))
  const setup = readFileSync(path.join(root, '../mfa-setup/index.html'), 'utf8')
  assert.ok(setup.includes('/qr-lib.js'), 'QR library must be loaded locally, not from a third-party URL')
  assert.ok(!setup.includes('fonts.googleapis'))
})
