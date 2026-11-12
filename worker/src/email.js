function codeEmailHtml(kind, code) {
  const signin = kind === 'signin'
  const title = signin ? 'Your sign-in code' : 'Your verification code'
  const lead = signin
    ? 'Use this code to finish signing in to your Kluzar account.'
    : 'Use this code to verify your email for your Kluzar account.'
  return '<!doctype html><html><body style="margin:0;padding:0;background-color:#f7f7fa;">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f7f7fa;"><tr><td align="center" style="padding:32px 16px;">' +
    '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background-color:#ffffff;border:1px solid #e8e7f0;border-radius:16px;">' +
    '<tr><td style="height:4px;background-color:#7c5cff;font-size:0;line-height:0;border-radius:14px 14px 0 0;">&nbsp;</td></tr>' +
    '<tr><td style="padding:28px 32px 0;"><img src="https://kluzar.com/logo.png" alt="Kluzar" width="150" style="display:block;width:150px;height:auto;border:0;" /></td></tr>' +
    '<tr><td style="padding:24px 32px 8px;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#131130;font-size:24px;font-weight:700;line-height:1.3;">' + title + '</td></tr>' +
    '<tr><td style="padding:0 32px 20px;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#26233f;font-size:15px;line-height:1.6;">' + lead + '</td></tr>' +
    '<tr><td style="padding:0 32px 8px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="background-color:#f7f7fa;border:1px solid #d9d7e8;border-radius:12px;padding:20px 16px;font-family:ui-monospace,\'SF Mono\',Menlo,Consolas,monospace;color:#141272;font-size:32px;font-weight:700;letter-spacing:10px;">' + code + '</td></tr></table></td></tr>' +
    '<tr><td style="padding:8px 32px 20px;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#76738f;font-size:14px;line-height:1.6;">This code expires in 15 minutes. If you did not request this code, you can ignore this email.</td></tr>' +
    '<tr><td style="padding:0 32px 12px;"><a href="https://kluzar.com" style="display:inline-block;background-color:#7c5cff;color:#ffffff;text-decoration:none;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;font-weight:700;font-size:15px;padding:13px 24px;border-radius:999px;">Visit kluzar.com</a></td></tr>' +
    '<tr><td style="padding:0 32px 28px;"><a href="https://contact.kluzar.com" style="display:inline-block;background-color:#ffffff;color:#141272;text-decoration:none;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;font-weight:700;font-size:14px;padding:11px 20px;border:1px solid #d9d7e8;border-radius:999px;margin-right:8px;">Contact</a><a href="https://support.kluzar.com" style="display:inline-block;background-color:#ffffff;color:#141272;text-decoration:none;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;font-weight:700;font-size:14px;padding:11px 20px;border:1px solid #d9d7e8;border-radius:999px;">Support</a></td></tr>' +
    '<tr><td style="padding:0 32px 28px;font-family:-apple-system,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;color:#76738f;font-size:13px;line-height:1.6;border-top:1px solid #e8e7f0;">Kluzar Accounts &middot; Your Business, Online &amp; Managed.<br />Questions? Email us at <a href="mailto:info@kluzar.com" style="color:#7c5cff;text-decoration:none;">info@kluzar.com</a></td></tr>' +
    '</table></td></tr></table></body></html>'
}

function codeEmailText(kind, code) {
  const signin = kind === 'signin'
  const title = signin ? 'Your Kluzar sign-in code is: ' : 'Your Kluzar verification code is: '
  return title + code + '\nThis code expires in 15 minutes. If you did not request this code, you can ignore this email.\nVisit Kluzar: https://kluzar.com\nContact: https://contact.kluzar.com\nSupport: https://support.kluzar.com\nQuestions? Email info@kluzar.com'
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
    htmlContent: codeEmailHtml('verification', code),
    textContent: codeEmailText('verification', code),
  })
}

export async function sendSignInEmail(env, email, code) {
  return sendBrevoEmail(env, {
    sender: { name: 'Kluzar accounts OTP', email: 'verify@kluzar.com' },
    to: [{ email }],
    replyTo: { email: 'info@kluzar.com' },
    subject: 'Your Kluzar sign-in code',
    htmlContent: codeEmailHtml('signin', code),
    textContent: codeEmailText('signin', code),
  })
}
