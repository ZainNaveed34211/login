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
    htmlContent: '<p>Your Kluzar verification code is:</p><p><strong>' + code + '</strong></p><p>This code expires in 15 minutes. If you did not request this code, you can ignore this email.</p>',
    textContent: 'Your Kluzar verification code is: ' + code + '\nThis code expires in 15 minutes. If you did not request this code, you can ignore this email.',
  })
}

export async function sendSignInEmail(env, email, code) {
  return sendBrevoEmail(env, {
    sender: { name: 'Kluzar accounts OTP', email: 'verify@kluzar.com' },
    to: [{ email }],
    replyTo: { email: 'info@kluzar.com' },
    subject: 'Your Kluzar sign-in code',
    htmlContent: '<p>Your Kluzar sign-in code is:</p><p><strong>' + code + '</strong></p><p>This code expires in 15 minutes. If you did not request this code, you can ignore this email.</p>',
    textContent: 'Your Kluzar sign-in code is: ' + code + '\nThis code expires in 15 minutes. If you did not request this code, you can ignore this email.',
  })
}
