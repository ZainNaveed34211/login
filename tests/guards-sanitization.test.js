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
  assert.ok(shared.includes("if (!codes.length) { go('/login/'); return }"), 'recovery codes page must require codes in storage')
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
  assert.equal(isValidPassword('long-enough-password-123'), true)
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
