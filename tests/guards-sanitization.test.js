import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { isValidName, isValidPhone, isValidEmail, isValidPassword } from '../worker/src/security.js'

const root = path.dirname(fileURLToPath(import.meta.url))
const shared = readFileSync(path.join(root, '../shared.js'), 'utf8')

test('guards: requireSession fails closed - any session failure redirects to /login/, never stays on a protected page', () => {
  const start = shared.indexOf('async function requireSession()')
  assert.ok(start >= 0, 'requireSession must exist')
  const body = shared.slice(start, shared.indexOf('function renderRecoveryCodes', start))
  assert.ok(body.includes("go('/login/')"), 'requireSession failure must redirect to /login/')
  assert.ok(!body.includes('showError'), 'requireSession failure must not just show an error and stay on the page')
  assert.ok(!body.includes("go('/expired/')"), 'requireSession must not send never-logged-in users to an expired page')
  assert.ok(body.includes("document.body.style.visibility = 'visible'"), 'session success must unhide a protected page')
})

test('guards: every protected page hides its body until the session is verified', () => {
  for (const folder of ['dashboard', 'profile', 'change-password', 'authenticator', 'sessions', 'recovery-codes/regenerate']) {
    const html = readFileSync(path.join(root, `../${folder}/index.html`), 'utf8')
    assert.ok(html.includes('visibility:hidden'), `${folder} must hide its body until verified`)
  }
  // Public pages must NOT be hidden, or a logged-out user sees nothing.
  for (const folder of ['login', 'signup', 'forget-password']) {
    const html = readFileSync(path.join(root, `../${folder}/index.html`), 'utf8')
    assert.ok(!html.includes('visibility:hidden'), `${folder} must stay visible without a session`)
  }
})

test('guards: step order - password page needs a valid email, MFA needs a challenge, reset needs a recovery token', () => {
  assert.ok(shared.includes("if (!isEmailFormat(email))"), 'password page must validate the stored email format, not just its presence')
  assert.ok(shared.includes("if (!challengeToken) { go('/login/'); return }"), 'MFA verify must require a challenge token')
  assert.ok(shared.includes("if (!recoveryToken) { go('/forget-password/'); return }"), 'reset page must require a recovery token')
  assert.ok(shared.includes("if (!codes.length) {"), 'recovery codes page must require codes in storage (then decide dashboard vs login by session, see session-on-every-page test)')
  assert.ok(!shared.includes("'mfa-manage'"), 'old mfa-manage page name must not remain in the chrome list')
  assert.ok(shared.includes("'authenticator'"), 'authenticator page must be in the protected list')
})

test('sanitization: frontend never renders user-controlled data as HTML', () => {
  // user_agent is still read (for display) but must only ever reach the
  // page via textContent, never via an HTML string.
  assert.ok(shared.includes("span.textContent = (s.current"), 'sessions list must use textContent')
  assert.ok(shared.includes('user_agent.slice(0, 60)'), 'user_agent display is still present, via textContent only')
  // Header/footer innerHTML is static only - no user variable in those lines.
  for (const line of shared.split('\n')) {
    if (line.includes('innerHTML') && !line.includes("innerHTML = ''")) {
      assert.ok(!line.includes('user') && !line.includes('email') && !line.includes('name') && !line.includes('phone'),
        `innerHTML line must not contain user data: ${line.trim()}`)
    }
  }
})

test('sanitization: frontend validates input before sending it to the API', () => {
  for (const fn of ['isEmailFormat', 'isPasswordOk', 'isCodeFormat', 'isNameOk', 'isPhoneOk']) {
    assert.ok(shared.includes(fn), `shared.js must define ${fn}`)
  }
  assert.ok(shared.includes("if (!isCodeFormat($('mfa-code').value))"), 'MFA code must be checked client-side')
  assert.ok(shared.includes("if (!isPasswordOk($('change-new').value))"), 'new password must be checked client-side')
})

test('sanitization: backend rejects markup in names and bad phone characters', () => {
  assert.equal(isValidName('Zain Naveed'), true)
  assert.equal(isValidName(''), true)
  assert.equal(isValidName('<script>alert(1)</script>'), false)
  assert.equal(isValidName('A & B'), false)
  assert.equal(isValidName('x'.repeat(101)), false)
  assert.equal(isValidPhone('+92 328 5049744'), true)
  assert.equal(isValidPhone(''), true)
  assert.equal(isValidPhone('<img src=x onerror=alert(1)>'), false)
  assert.equal(isValidPhone('abc'), false)
  assert.equal(isValidPhone('123456789012345678901234567890123456789012345678901'), false)
  assert.equal(isValidEmail('zain@example.com'), true)
  assert.equal(isValidEmail('not-an-email'), false)
  assert.equal(isValidPassword('short'), false)
  assert.equal(isValidPassword('Long-enough-Password-123!'), true)
  // Simple passwords must be rejected even at 12+ characters: mixed
  // characters (lowercase, uppercase, digit, symbol) are required.
  assert.equal(isValidPassword('aaaaaaaaaaaa'), false)
  assert.equal(isValidPassword('123456789012'), false)
  assert.equal(isValidPassword('long-enough-password-123'), false)
  assert.equal(isValidPassword('LongEnoughPassword'), false)
  assert.equal(isValidPassword('x'.repeat(129)), false)
})

test('sanitization: backend token tables are allowlisted, never built from user input', () => {
  const handlers = readFileSync(path.join(root, '../worker/src/handlers.js'), 'utf8')
  assert.ok(handlers.includes('ONE_TIME_TABLES'), 'token table allowlist must exist')
  assert.ok(handlers.includes("checkOneTimeTable(table)"), 'token functions must check the allowlist')
  // Callers pass only hardcoded table names.
  for (const name of ['setup_tokens', 'login_challenges', 'recovery_transactions']) {
    assert.ok(handlers.includes(`'${name}'`), `hardcoded table ${name} must exist`)
  }
})

test('session on every page: already-logged-in users are sent to dashboard from login/signup/password/code/expired, never left on a step page', () => {
  assert.ok(shared.includes('async function redirectIfAuthed()'), 'redirectIfAuthed helper must exist')
  for (const page of ["page === 'login-password'", "page === 'signup'", "page === 'mfa-verify'", "page === 'expired'"]) {
    const idx = shared.indexOf(page)
    assert.ok(idx >= 0, `${page} handler must exist`)
    const block = shared.slice(idx, idx + 400)
    assert.ok(block.includes('redirectIfAuthed'), `${page} must check session and redirect to dashboard if already logged in`)
  }
  assert.ok(shared.includes("page === 'login-email'"), 'login-email must keep its existing dashboard redirect')
})

test('session on every page: protected forms redirect to login on 401, not just show an error', () => {
  assert.ok(shared.includes('function handleProtectedError'), 'handleProtectedError helper must exist')
  const count = (shared.match(/handleProtectedError\(err\)/g) || []).length
  assert.ok(count >= 6, `handleProtectedError must be used in protected handlers, found ${count}`)
})

test('session on every page: recovery-codes without codes goes to dashboard if logged in, else login', () => {
  const idx = shared.indexOf("page === 'recovery-codes'")
  const block = shared.slice(idx, idx + 600)
  assert.ok(block.includes("go('/dashboard/')"), 'recovery-codes without codes must go to dashboard when logged in')
  assert.ok(block.includes("go('/login/')"), 'recovery-codes without codes must go to login when logged out')
})

test('production copy: 404 page must not contain internal talk about clean paths or .html addresses', () => {
  const html = readFileSync(path.join(root, '../404.html'), 'utf8')
  assert.ok(!html.includes('clean path'), '404 must not mention clean paths - that is internal talk')
  assert.ok(!html.includes('.html in the address'), '404 must not mention .html addresses')
  assert.ok(html.includes('Page not found'), '404 must still say the page was not found')
  assert.ok(html.includes('/login/'), '404 must link to sign-in')
})

test('redirect fix: every protected page has an inline session guard in <head>, independent of shared.js', () => {
  for (const folder of ['dashboard', 'profile', 'change-password', 'authenticator', 'sessions', 'recovery-codes/regenerate']) {
    const html = readFileSync(path.join(root, `../${folder}/index.html`), 'utf8')
    const head = html.split('<body')[0]
    assert.ok(head.includes("fetch('https://account-api.kluzar.com/auth/session'"), `${folder} must check the session inline in <head>`)
    assert.ok(head.includes("window.location.href='/login/'"), `${folder} inline guard must redirect to /login/ on failure`)
  }
  // Public pages must NOT get the inline session redirect (login/signup flows would break).
  for (const folder of ['login', 'signup', 'forget-password']) {
    const html = readFileSync(path.join(root, `../${folder}/index.html`), 'utf8')
    assert.ok(!html.split('<body')[0].includes("fetch('https://account-api.kluzar.com/auth/session'"), `${folder} must not have an inline session redirect`)
  }
})

test('deploy method: D1 ID comes from a GitHub variable, never a secret, never a file edit', () => {
  const deploy = readFileSync(path.join(root, '../.github/workflows/deploy.yml'), 'utf8')
  assert.ok(deploy.includes('vars.KLUZAR_ACCOUNTS_D1_ID'), 'deploy must use the GitHub variable for the D1 ID')
  assert.ok(!deploy.includes('secrets.KLUZAR_ACCOUNTS_D1_ID'), 'deploy must not use a secret for the D1 ID')
  const wrangler = readFileSync(path.join(root, '../wrangler.toml'), 'utf8')
  assert.ok(wrangler.includes('REPLACE_WITH_REAL_D1_DATABASE_ID'), 'wrangler.toml must keep the placeholder, never a real ID')
  assert.ok(!/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/.test(wrangler), 'wrangler.toml must not contain a real D1 ID')
})

test('logo/favicon rule: every index page and 404 loads favicon.js, and favicon.js is the exact main-site favicon', () => {
  const pages = [
    'index.html', '404.html',
    'login/index.html', 'login/password/index.html', 'login/code/index.html',
    'signup/index.html', 'mfa-setup/index.html', 'recovery-codes/index.html',
    'forget-password/index.html', 'forget-password/reset/index.html',
    'dashboard/index.html', 'profile/index.html', 'change-password/index.html',
    'authenticator/index.html', 'sessions/index.html',
    'recovery-codes/regenerate/index.html', 'expired/index.html',
  ]
  assert.equal(pages.length, 17)
  for (const page of pages) {
    const html = readFileSync(path.join(root, `../${page}`), 'utf8')
    assert.ok(html.includes('<script src="/favicon.js"></script>'), `${page} must load favicon.js`)
  }
  const faviconJs = readFileSync(path.join(root, '../favicon.js'), 'utf8')
  assert.ok(faviconJs.includes('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAgAAAAG9CAYAAABjxM7'), 'favicon.js must start with the exact main-site favicon data')
  assert.ok(faviconJs.includes("setFavicon('icon'"), 'favicon.js must set the tab icon')
  assert.ok(faviconJs.includes("setFavicon('apple-touch-icon'"), 'favicon.js must set the touch icon')
})
