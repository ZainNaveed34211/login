import test from 'node:test'
import assert from 'node:assert/strict'
import { sendVerificationEmail, sendSignInEmail } from '../worker/src/email.js'
import { stubBrevo } from './helpers.js'

const CODE = '482917'

async function capture(sendFn) {
  const stub = stubBrevo()
  try {
    const ok = await sendFn({ BREVO_API_KEY: 'test-brevo-key' }, 'template@example.com', CODE)
    assert.equal(ok, true)
    assert.equal(stub.sent.length, 1)
    return JSON.parse(stub.sent[0].options.body)
  } finally {
    stub.restore()
  }
}

for (const [name, sendFn, subject, title] of [
  ['verification', sendVerificationEmail, 'Your Kluzar verification code', 'Your verification code'],
  ['sign-in', sendSignInEmail, 'Your Kluzar sign-in code', 'Your sign-in code'],
]) {
  test(name + ' email keeps sender, subject and plain-text code', async () => {
    const body = await capture(sendFn)
    assert.equal(body.sender.email, 'verify@kluzar.com')
    assert.equal(body.sender.name, 'Kluzar accounts OTP')
    assert.equal(body.replyTo.email, 'info@kluzar.com')
    assert.equal(body.subject, subject)
    assert.equal(body.to[0].email, 'template@example.com')
    assert.match(body.textContent, new RegExp('^[^\\d]*' + CODE))
    assert.match(body.textContent, /15 minutes/)
    assert.match(body.textContent, /https:\/\/kluzar\.com/)
    assert.match(body.textContent, /https:\/\/contact\.kluzar\.com/)
    assert.match(body.textContent, /https:\/\/support\.kluzar\.com/)
    assert.doesNotMatch(body.textContent, /Promotions tab/)
  })

  test(name + ' email html is a branded inline-styled template', async () => {
    const body = await capture(sendFn)
    assert.ok(body.htmlContent.includes(title))
    assert.ok(body.htmlContent.includes(CODE))
    assert.ok(body.htmlContent.includes('https://kluzar.com/logo.png'))
    assert.ok(body.htmlContent.includes('href="https://kluzar.com"'))
    assert.ok(body.htmlContent.includes('href="https://contact.kluzar.com"'))
    assert.ok(body.htmlContent.includes('href="https://support.kluzar.com"'))
    assert.ok(body.htmlContent.includes('info@kluzar.com'))
    assert.ok(body.htmlContent.includes('#141272'))
    assert.ok(body.htmlContent.includes('#7c5cff'))
    assert.doesNotMatch(body.htmlContent, /<script/i)
    assert.doesNotMatch(body.htmlContent, /<style/i)
    assert.doesNotMatch(body.htmlContent, /@import|fonts\.googleapis|fonts\.gstatic/i)
    assert.doesNotMatch(body.htmlContent, /Promotions tab/)
  })
}

test('email send returns false without a Brevo key', async () => {
  assert.equal(await sendVerificationEmail({}, 'template@example.com', CODE), false)
  assert.equal(await sendSignInEmail({}, 'template@example.com', CODE), false)
})
