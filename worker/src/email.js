import { changesOf } from './db.js'

function escapeHtml(v) {
  return String(v || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

function footerHtml() {
  return '<tr><td style="background-color:#f7f7fa;border-top:1px solid #e8e7f0;padding:18px 24px 20px;text-align:center;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#76738f;font-size:12px;line-height:1.9;">' +
    '&copy; ' + new Date().getFullYear() + ' Kluzar. All rights reserved.<br />' +
    '<a href="https://contact.kluzar.com" style="color:#7c5cff;text-decoration:none;">Contact</a> &middot; ' +
    '<a href="https://support.kluzar.com" style="color:#7c5cff;text-decoration:none;">Support</a> &middot; ' +
    '<a href="https://kluzar.com" style="color:#7c5cff;text-decoration:none;">Visit Web</a><br />' +
    'Questions? Email us at <a href="mailto:info@kluzar.com" style="color:#7c5cff;text-decoration:none;">info@kluzar.com</a></td></tr>'
}

function footerText() {
  return '\n\u00a9 ' + new Date().getFullYear() + ' Kluzar. All rights reserved.\nContact: https://contact.kluzar.com\nSupport: https://support.kluzar.com\nVisit Web: https://kluzar.com\nQuestions? Email info@kluzar.com'
}

function codeEmailHtml(kind, code, email) {
  const signin = kind === 'signin'
  const title = signin ? 'Your OTP Code' : 'Verify your email address'
  const lead = signin
    ? 'Your One-Time Password (OTP) to sign in to your Kluzar account is:'
    : 'Your One-Time Password (OTP) for account verification is:'
  return '<!doctype html><html><body style="margin:0;padding:0;background-color:#f4f3fa;">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f3fa;"><tr><td align="center" style="padding:32px 16px;">' +
    '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background-color:#ffffff;border:1px solid #e8e7f0;border-radius:16px;">' +
    '<tr><td align="center" style="padding:28px 24px 20px;"><img src="https://kluzar.com/logo.png" alt="Kluzar" width="150" style="display:block;width:150px;height:auto;border:0;" /></td></tr>' +
    '<tr><td align="center" style="background-color:#7c5cff;padding:22px 24px;"><div style="color:#ffffff;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;font-size:26px;font-weight:700;line-height:1.25;">' + title + '</div></td></tr>' +
    '<tr><td style="padding:28px 24px 8px;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#26233f;font-size:15px;line-height:1.6;">Hi, <b style="color:#141272;">' + escapeHtml(email) + '</b>,</td></tr>' +
    '<tr><td style="padding:0 24px 16px;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#26233f;font-size:15px;line-height:1.6;">' + lead + '</td></tr>' +
    '<tr><td align="center" style="padding:0 24px 20px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="background-color:#f2f1f7;border-radius:12px;padding:20px 16px;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#7c5cff;font-size:34px;font-weight:800;letter-spacing:8px;">' + escapeHtml(code) + '</td></tr></table></td></tr>' +
    '<tr><td style="padding:0 24px 8px;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#26233f;font-size:15px;line-height:1.6;">This OTP is valid for <b>15 minutes</b>. Please do not share this code with anyone.</td></tr>' +
    '<tr><td style="padding:0 24px 8px;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#26233f;font-size:15px;line-height:1.6;">If you didn\'t request this code, please ignore this email.</td></tr>' +
    '<tr><td style="padding:0 24px 28px;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#26233f;font-size:15px;line-height:1.6;">Thank you for using Kluzar!</td></tr>' +
    footerHtml() +
    '</table></td></tr></table></body></html>'
}

function codeEmailText(kind, code, email) {
  const signin = kind === 'signin'
  const lead = signin
    ? 'Your One-Time Password (OTP) to sign in to your Kluzar account is: '
    : 'Your One-Time Password (OTP) for account verification is: '
  return 'Hi, ' + email + ',\n' + lead + code + '\nThis OTP is valid for 15 minutes. Please do not share this code with anyone.\nIf you didn\'t request this code, please ignore this email.\nThank you for using Kluzar!' + footerText()
}

function welcomeEmailHtml() {
  return '<!doctype html><html><body style="margin:0;padding:0;background-color:#f4f3fa;">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f3fa;"><tr><td align="center" style="padding:32px 16px;">' +
    '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background-color:#ffffff;border:1px solid #e8e7f0;border-radius:16px;">' +
    '<tr><td style="padding:28px 24px 0;"><img src="https://kluzar.com/logo.png" alt="Kluzar" width="120" style="display:block;width:120px;height:auto;border:0;" /></td></tr>' +
    '<tr><td style="padding:24px 24px 0;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#141272;font-size:32px;font-weight:800;line-height:1.2;">Welcome!</td></tr>' +
    '<tr><td style="padding:16px 24px 0;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#26233f;font-size:16px;line-height:1.7;">Thank you for creating your Kluzar account.</td></tr>' +
    '<tr><td style="padding:12px 24px 0;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#26233f;font-size:16px;line-height:1.7;">If you need assistance, our support team is here to help. Please do not hesitate to <a href="https://contact.kluzar.com" style="color:#7c5cff;text-decoration:none;font-weight:700;">contact us</a> if you have any questions or concerns.</td></tr>' +
    '<tr><td style="padding:16px 24px 28px;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#26233f;font-size:16px;line-height:1.7;">Thanks again!</td></tr>' +
    footerHtml() +
    '</table></td></tr></table></body></html>'
}

function welcomeEmailText() {
  return 'Welcome!\n\nThank you for creating your Kluzar account.\n\nIf you need assistance, our support team is here to help. Please do not hesitate to contact us (https://contact.kluzar.com) if you have any questions or concerns.\n\nThanks again!' + footerText()
}

async function sendBrevoEmail(env, payload) {
  const apiKey = env.BREVO_API_KEY
  if (!apiKey) return false
  let res
  try {
    res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'api-key': apiKey },
      body: JSON.stringify(payload),
    })
  } catch {
    return false
  }
  if (!res || !res.ok) return false
  return true
}

export async function sendVerificationEmail(env, email, code) {
  return sendBrevoEmail(env, {
    sender: { name: 'Kluzar accounts OTP', email: 'verify@kluzar.com' },
    to: [{ email }],
    replyTo: { email: 'info@kluzar.com' },
    subject: 'Your Kluzar verification code',
    htmlContent: codeEmailHtml('verification', code, email),
    textContent: codeEmailText('verification', code, email),
  })
}

export async function sendSignInEmail(env, email, code) {
  return sendBrevoEmail(env, {
    sender: { name: 'Kluzar accounts OTP', email: 'verify@kluzar.com' },
    to: [{ email }],
    replyTo: { email: 'info@kluzar.com' },
    subject: 'Your Kluzar sign-in code',
    htmlContent: codeEmailHtml('signin', code, email),
    textContent: codeEmailText('signin', code, email),
  })
}

export async function sendWelcomeEmail(env, email) {
  return sendBrevoEmail(env, {
    sender: { name: 'Kluzar', email: 'hello@kluzar.com' },
    to: [{ email }],
    replyTo: { email: 'info@kluzar.com' },
    subject: 'Welcome to Kluzar',
    htmlContent: welcomeEmailHtml(),
    textContent: welcomeEmailText(),
  })
}

export async function sendWelcomeEmailOnce(env, userId, email) {
  if (!env || !env.DB || !userId || !email) return false
  let claimed
  try {
    claimed = await env.DB.prepare('UPDATE users SET welcome_email_sent = ? WHERE id = ? AND welcome_email_sent = ?').bind(1, userId, 0).run()
  } catch {
    return false
  }
  if (changesOf(claimed) !== 1) return false
  let ok = false
  try {
    ok = await sendWelcomeEmail(env, email)
  } catch {
    ok = false
  }
  if (!ok) {
    try {
      await env.DB.prepare('UPDATE users SET welcome_email_sent = ? WHERE id = ?').bind(0, userId).run()
    } catch {
    }
  }
  return ok
}
