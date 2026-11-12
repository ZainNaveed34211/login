import test from 'node:test'
import assert from 'node:assert/strict'
import { sendVerificationEmail, sendSignInEmail } from '../worker/src/email.js'
import { stubBrevo } from './helpers.js'

const CODE = '482917'
const EVIL_EMAIL = 'a"><script>alert(1)</script>@example.com'
const EVIL_EMAIL_ESCAPED = 'a&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;@example.com'
const YEAR = String(new Date().getFullYear())

async function capture(sendFn, email) {
  const stub = stubBrevo()
  try {
    const ok = await sendFn({ BREVO_API_KEY: 'test-brevo-key' }, email || 'template@example.com', CODE)
    assert.equal(ok, true)
    assert.equal(stub.sent.length, 1)
    return JSON.parse(stub.sent[0].options.body)
  } finally {
    stub.restore()
  }
}

function textOf(html) {
  return html.replace(/<[^>]*>/g, '')
}

for (const [name, sendFn, subject, title, verifyUrl] of [
  ['verification', sendVerificationEmail, 'Your Kluzar verification code', 'Verify your email address', 'https://accounts.kluzar.com/signup/verify/'],
  ['sign-in', sendSignInEmail, 'Your Kluzar sign-in code', 'Your OTP Code', 'https://accounts.kluzar.com/login/code/'],
]) {
  test(name + ' email keeps sender, subject and plain-text code', async () => {
    const body = await capture(sendFn)
    assert.equal(body.sender.email, 'verify@kluzar.com')
    assert.equal(body.sender.name, 'Kluzar accounts OTP')
    assert.equal(body.replyTo.email, 'info@kluzar.com')
    assert.equal(body.subject, subject)
    assert.equal(body.to[0].email, 'template@example.com')
    assert.ok(body.textContent.includes('Hi, template@example.com,'))
    assert.match(body.textContent, new RegExp('^[^\\d]*' + CODE))
    assert.match(body.textContent, /15 minutes/)
    assert.ok(body.textContent.includes('Please do not share this code with anyone'))
    assert.ok(body.textContent.includes("If you didn't request this code"))
    assert.ok(body.textContent.includes('Thank you for using Kluzar!'))
    assert.ok(body.textContent.includes(verifyUrl))
    assert.match(body.textContent, /https:\/\/kluzar\.com/)
    assert.match(body.textContent, /https:\/\/contact\.kluzar\.com/)
    assert.match(body.textContent, /https:\/\/support\.kluzar\.com/)
    assert.doesNotMatch(body.textContent, /Promotions tab/)
    assert.doesNotMatch(body.textContent, /This code was sent to/)
  })

  test(name + ' email html is a branded inline-styled template', async () => {
    const body = await capture(sendFn)
    assert.ok(body.htmlContent.includes(title))
    assert.ok(body.htmlContent.includes('https://kluzar.com/logo.png'))
    assert.ok(body.htmlContent.includes('href="https://kluzar.com"'))
    assert.ok(body.htmlContent.includes('href="https://contact.kluzar.com"'))
    assert.ok(body.htmlContent.includes('href="https://support.kluzar.com"'))
    assert.ok(body.htmlContent.includes('info@kluzar.com'))
    assert.ok(body.htmlContent.includes('#141272'))
    assert.ok(body.htmlContent.includes('#7c5cff'))
    assert.ok(body.htmlContent.includes('&copy; ' + YEAR + ' Kluzar. All rights reserved.'))
    assert.doesNotMatch(body.htmlContent, /<script/i)
    assert.doesNotMatch(body.htmlContent, /<style/i)
    assert.doesNotMatch(body.htmlContent, /@import|fonts\.googleapis|fonts\.gstatic/i)
    assert.doesNotMatch(body.htmlContent, /Promotions tab/)
    assert.doesNotMatch(body.htmlContent, /This code was sent to/)
  })

  test(name + ' email shows the code as one plain string on a single grey bar, not per-digit boxes', async () => {
    const body = await capture(sendFn)
    assert.doesNotMatch(body.htmlContent, /border:2px solid #d9d7e8/)
    assert.ok(body.htmlContent.includes('>' + CODE + '</td>'))
    assert.ok(body.htmlContent.includes('background-color:#f2f1f7'))
    assert.ok(body.htmlContent.includes('color:#7c5cff'))
  })

  test(name + ' email code reads as one contiguous code for Gmail OTP detection', async () => {
    const body = await capture(sendFn)
    const text = textOf(body.htmlContent)
    assert.ok(text.includes(CODE))
    assert.deepEqual(text.match(/\d{6}/g), [CODE])
    assert.ok(body.textContent.includes(CODE))
  })

  test(name + ' email greets with the recipient address, escaped in html', async () => {
    const body = await capture(sendFn, EVIL_EMAIL)
    assert.ok(body.htmlContent.includes('Hi,'))
    assert.ok(body.htmlContent.includes(EVIL_EMAIL_ESCAPED))
    assert.doesNotMatch(body.htmlContent, /<script/i)
    assert.ok(!body.htmlContent.includes(EVIL_EMAIL))
    assert.ok(body.textContent.includes('Hi, ' + EVIL_EMAIL + ','))
  })

  test(name + ' email button goes to the verify page and footer links are small text links only', async () => {
    const body = await capture(sendFn)
    assert.ok(body.htmlContent.includes('href="' + verifyUrl + '"'))
    assert.ok(body.htmlContent.includes('>Enter your code</a>'))
    assert.doesNotMatch(body.htmlContent, />Copy code</)
    assert.doesNotMatch(body.htmlContent, />Verify Email</)
    assert.equal((body.htmlContent.match(/border-radius:999px/g) || []).length, 1)
    assert.ok(body.htmlContent.includes('href="https://contact.kluzar.com"'))
    assert.ok(body.htmlContent.includes('>Contact</a>'))
    assert.ok(body.htmlContent.includes('href="https://support.kluzar.com"'))
    assert.ok(body.htmlContent.includes('>Support</a>'))
    assert.ok(body.htmlContent.includes('href="https://kluzar.com"'))
    assert.ok(body.htmlContent.includes('>Visit Web</a>'))
  })
}

test('email send returns false without a Brevo key', async () => {
  assert.equal(await sendVerificationEmail({}, 'template@example.com', CODE), false)
  assert.equal(await sendSignInEmail({}, 'template@example.com', CODE), false)
})
