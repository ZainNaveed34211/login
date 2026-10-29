// Kluzar Accounts — shared code for the separate-pages frontend.
// WHY separate pages: the old single-page version kept every step in one
// HTML file and all progress in memory, so a refresh always went back to
// the email screen. Now every step is its own page (its own URL), so a
// refresh stays on the same page.
//
// WHAT survives a refresh, and what does not (security rules):
// - Session: the HttpOnly cookie set by the API. It survives refresh and
//   is NEVER stored in localStorage/sessionStorage.
// - Email address: sessionStorage only (not a credential).
// - Temporary one-time tokens (setupToken, challengeToken, recoveryToken):
//   sessionStorage only, tab-scoped, cleared on tab close, NEVER in a URL
//   (URLs leak into logs/history) and NEVER in localStorage (persistent).
// - Passwords: NEVER stored anywhere in the browser.
// - Recovery codes shown on the recovery pages: sessionStorage only,
//   cleared as soon as the user confirms they saved them.
// - MFA setup QR/manual key: NOT stored. On refresh of the setup page the
//   stored setupToken is used to fetch a FRESH setup (new QR/key); the
//   old QR stops working, which is the safe behaviour.
// - CSRF token: NOT stored. Every authenticated page fetches it fresh
//   from GET /auth/session (the session cookie authenticates that call).
// - Re-setup password: NEVER stored either. The setup page itself asks
//   for the current password when re-setting up MFA from a session.
(function () {
  'use strict'
  const API = window.KLUZAR_CONFIG.API_BASE_URL
  const PAYMENTS_URL = window.KLUZAR_CONFIG.PAYMENTS_URL
  const S = window.sessionStorage
  const $ = (id) => document.getElementById(id)
  const go = (page) => { window.location.href = page }
  function showError(msg) {
    const el = $('global-error')
    if (!el) { alert(msg); return }
    el.textContent = msg
    el.classList.remove('hidden')
  }
  function showInfo(msg) {
    const el = $('global-info')
    if (!el) return
    el.textContent = msg
    el.classList.remove('hidden')
  }
  async function api(path, options = {}) {
    const res = await fetch(API + path, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    })
    let data = {}
    try { data = await res.json() } catch { data = {} }
    if (!res.ok) {
      const err = new Error(data.error || 'Something went wrong. Please try again.')
      err.status = res.status
      err.data = data
      throw err
    }
    return data
  }
  function renderChrome(authed) {
    const header = $('site-header')
    if (header) {
      header.innerHTML = '<div class="topbar-inner">' +
        '<a class="brand" href="/login/"><img id="brand-logo" alt="Kluzar" /><span>Accounts</span></a>' +
        '<nav class="topnav" aria-label="Account">' +
        (authed ? '<button type="button" id="nav-dashboard" class="nav-btn">Dashboard</button><button type="button" id="nav-logout" class="nav-btn">Log out</button>' : '') +
        '</nav></div>'
      if (window.KLUZAR_LOGO_URL) $('brand-logo').src = window.KLUZAR_LOGO_URL
      const dash = $('nav-dashboard')
      if (dash) dash.addEventListener('click', () => go('/dashboard/'))
      const out = $('nav-logout')
      if (out) out.addEventListener('click', logout)
    }
    const footer = $('site-footer')
    if (footer) footer.innerHTML = '<p>Kluzar Accounts · Your Business, Online &amp; Managed.</p>'
  }
  async function logout() {
    try { await api('/auth/logout', { method: 'POST', body: JSON.stringify({}) }) } catch { /* ignore */ }
    S.clear()
    go('/login/')
  }
  async function requireSession() {
    try {
      const session = await api('/auth/session', { method: 'GET' })
      renderChrome(true)
      return session
    } catch (err) {
      renderChrome(false)
      if (err.status === 401) go('/expired/')
      else showError(err.message)
      return null
    }
  }
  function renderRecoveryCodes(codes, listEl) {
    listEl.innerHTML = ''
    codes.forEach((c) => { const li = document.createElement('li'); li.textContent = c; listEl.appendChild(li) })
  }
  function downloadCodes(codes, filename) {
    const blob = new Blob(['Kluzar recovery codes — store these somewhere safe. Each code works once.\n\n' + codes.join('\n') + '\n'], { type: 'text/plain' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = filename
    a.click()
    URL.revokeObjectURL(a.href)
  }
  function renderEntitlement(ent) {
    $('entitlement-loading').classList.add('hidden')
    if (!ent) {
      $('entitlement-error').classList.remove('hidden')
      $('entitlement-content').classList.add('hidden')
      return
    }
    $('entitlement-error').classList.add('hidden')
    $('entitlement-content').classList.remove('hidden')
    $('ent-plan').textContent = ent.plan
    $('ent-status').textContent = ent.status
    $('ent-note').textContent = ent.premium
      ? 'You already have Premium access. Get Premium is hidden because your plan already grants it.'
      : 'You are on the free plan. Get Premium to unlock deeper scans, premium findings and branded reports.'
    const btn = $('get-premium-btn')
    // Show only when server-verified Free, hide when paid. Loading/error
    // states above never assume Free or paid.
    btn.classList.toggle('hidden', !!ent.premium)
    btn.href = PAYMENTS_URL
  }
  async function loadDashboard() {
    const session = await requireSession()
    if (!session) return
    $('dash-email').textContent = session.user.email
    $('dash-verified').textContent = session.user.emailVerified ? 'Email verified' : 'Email not yet verified (verification is not implemented in this phase)'
    $('dash-name').textContent = [session.user.firstName, session.user.lastName].filter(Boolean).join(' ') || '—'
    $('dash-phone').textContent = session.user.phone || '—'
    $('dash-mfa').textContent = session.user.mfaEnabled ? 'On' : 'Off'
    renderEntitlement(session.entitlement)
    const logoutAll = $('dash-logout-all')
    if (logoutAll) logoutAll.addEventListener('click', async () => {
      try {
        await api('/auth/logout-all', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({}) })
      } catch (err) { showError(err.message); return }
      S.clear()
      go('/login/')
    })
    const retry = $('entitlement-retry')
    if (retry) retry.addEventListener('click', () => window.location.reload())
  }
  // Page dispatch — document.body.dataset.page is set in each page's HTML.
  const page = document.body ? document.body.dataset.page : ''
  document.addEventListener('DOMContentLoaded', async () => {
    // Pages that need no session render chrome unauthenticated by default.
    if (!['dashboard', 'profile', 'password-change', 'mfa-manage', 'sessions', 'recovery-regenerate'].includes(page)) renderChrome(false)

    if (page === 'login-email') {
      $('form-email').addEventListener('submit', (e) => {
        e.preventDefault()
        S.setItem('kluzar_email', $('email-input').value.trim())
        S.setItem('kluzar_password_failures', '0')
        go('/login/password/')
      })
      $('go-signup').addEventListener('click', () => go('/signup/'))
      $('go-forgot-1').addEventListener('click', () => go('/forget-password/'))
      // If already logged in, go straight to dashboard.
      try { const s = await api('/auth/session', { method: 'GET' }); if (s.authenticated) go('/dashboard/') } catch { /* stay */ }
    }

    if (page === 'login-password') {
      const email = S.getItem('kluzar_email') || ''
      if (!email) { go('/login/'); return }
      $('password-email-label').textContent = email
      $('back-to-email').addEventListener('click', () => go('/login/'))
      $('go-forgot-2').addEventListener('click', () => go('/forget-password/'))
      $('form-password').addEventListener('submit', async (e) => {
        e.preventDefault()
        try {
          const data = await api('/auth/login', { method: 'POST', body: JSON.stringify({ email, password: $('password-input').value }) })
          S.setItem('kluzar_password_failures', '0')
          if (data.setupRequired) { S.setItem('kluzar_setup_token', data.setupToken); go('/mfa-setup/'); return }
          if (data.mfaRequired) { S.setItem('kluzar_challenge_token', data.challengeToken); go('/login/code/'); return }
          go('/dashboard/')
        } catch (err) {
          // After 2 consecutive wrong passwords, back to email entry.
          // UI reset only — server-side abuse counters are NOT reset.
          const n = (parseInt(S.getItem('kluzar_password_failures') || '0', 10) || 0) + 1
          S.setItem('kluzar_password_failures', String(n))
          $('password-input').value = ''
          if (n >= 2) {
            S.setItem('kluzar_password_failures', '0')
            S.setItem('kluzar_notice', 'Too many incorrect attempts in this flow. Please start again from your email address.')
            go('/login/')
          } else showError(err.message)
        }
      })
    }

    if (page === 'signup') {
      $('back-to-login').addEventListener('click', () => go('/login/'))
      $('form-signup').addEventListener('submit', async (e) => {
        e.preventDefault()
        const email = $('signup-email').value.trim()
        const password = $('signup-password').value
        if (password !== $('signup-password2').value) { showError('Passwords do not match.'); return }
        try {
          const data = await api('/auth/register', { method: 'POST', body: JSON.stringify({ email, password }) })
          S.setItem('kluzar_email', email)
          S.setItem('kluzar_setup_token', data.setupToken)
          go('/mfa-setup/')
        } catch (err) { showError(err.message) }
      })
    }

    if (page === 'mfa-setup') {
      const setupToken = S.getItem('kluzar_setup_token')
      const sessionMode = !setupToken
      async function renderSetup(data) {
        $('manual-key').textContent = data.manualKey
        if (window.KluzarQRCode && window.KluzarQRCode.toDataURL) {
          $('qr-img').src = await window.KluzarQRCode.toDataURL(data.otpauthUrl, { width: 220, margin: 1 })
        }
        $('setup-qr-box').classList.remove('hidden')
      }
      if (sessionMode) {
        // Authenticated re-setup: ask for the current password ON THIS
        // PAGE (never stored, never passed through sessionStorage).
        const session = await requireSession()
        if (!session) return
        $('setup-password-box').classList.remove('hidden')
        $('setup-qr-box').classList.add('hidden')
        $('form-setup-password').addEventListener('submit', async (e) => {
          e.preventDefault()
          try {
            const data = await api('/auth/mfa/setup', { method: 'POST', body: JSON.stringify({ currentPassword: $('setup-current-password').value }) })
            $('setup-current-password').value = ''
            $('setup-password-box').classList.add('hidden')
            await renderSetup(data)
          } catch (err) { showError(err.message) }
        })
      } else {
        try {
          const data = await api('/auth/mfa/setup', { method: 'POST', body: JSON.stringify({ setupToken }) })
          if (data.setupToken) S.setItem('kluzar_setup_token', data.setupToken)
          await renderSetup(data)
        } catch (err) { showError(err.message) }
      }
      $('form-mfa-setup').addEventListener('submit', async (e) => {
        e.preventDefault()
        try {
          if (sessionMode) {
            await api('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ code: $('mfa-setup-code').value.trim() }) })
            go('/dashboard/')
            return
          }
          const data = await api('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ setupToken: S.getItem('kluzar_setup_token'), code: $('mfa-setup-code').value.trim() }) })
          S.removeItem('kluzar_setup_token')
          if (data.recoveryCodes) S.setItem('kluzar_recovery_codes', JSON.stringify(data.recoveryCodes))
          go('/recovery-codes/')
        } catch (err) { showError(err.message) }
      })
    }

    if (page === 'mfa-verify') {
      const challengeToken = S.getItem('kluzar_challenge_token')
      if (!challengeToken) { go('/login/'); return }
      $('form-mfa-verify').addEventListener('submit', async (e) => {
        e.preventDefault()
        try {
          await api('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ challengeToken, code: $('mfa-code').value.trim() }) })
          S.removeItem('kluzar_challenge_token')
          go('/dashboard/')
        } catch (err) { showError(err.message) }
      })
    }

    if (page === 'recovery-codes') {
      const codes = JSON.parse(S.getItem('kluzar_recovery_codes') || '[]')
      if (!codes.length) { go('/login/'); return }
      renderRecoveryCodes(codes, $('recovery-list'))
      $('download-codes').addEventListener('click', () => downloadCodes(codes, 'kluzar-recovery-codes.txt'))
      $('recovery-done').addEventListener('click', () => { S.removeItem('kluzar_recovery_codes'); go('/dashboard/') })
    }

    if (page === 'forget-password') {
      $('forgot-email').value = S.getItem('kluzar_email') || ''
      $('form-forgot').addEventListener('submit', async (e) => {
        e.preventDefault()
        try {
          const data = await api('/auth/password/forgot', { method: 'POST', body: JSON.stringify({ email: $('forgot-email').value.trim(), code: $('forgot-code').value.trim() }) })
          if (data.recoveryToken) {
            S.setItem('kluzar_recovery_token', data.recoveryToken)
            go('/forget-password/reset/')
          } else showInfo(data.message || 'If an account exists, a recovery step is available.')
        } catch (err) { showError(err.message) }
      })
    }

    if (page === 'forget-password-reset') {
      const recoveryToken = S.getItem('kluzar_recovery_token')
      if (!recoveryToken) { go('/forget-password/'); return }
      $('form-reset').addEventListener('submit', async (e) => {
        e.preventDefault()
        if ($('reset-password').value !== $('reset-password2').value) { showError('Passwords do not match.'); return }
        try {
          await api('/auth/password/reset', { method: 'POST', body: JSON.stringify({ recoveryToken, newPassword: $('reset-password').value }) })
          S.removeItem('kluzar_recovery_token')
          S.setItem('kluzar_notice', 'Password changed. Please sign in again with your new password and authenticator code.')
          go('/login/')
        } catch (err) { showError(err.message) }
      })
    }

    if (page === 'dashboard') { await loadDashboard() }

    if (page === 'profile') {
      const session = await requireSession()
      if (!session) return
      $('profile-first').value = session.user.firstName || ''
      $('profile-last').value = session.user.lastName || ''
      $('profile-phone').value = session.user.phone || ''
      $('form-profile').addEventListener('submit', async (e) => {
        e.preventDefault()
        try {
          await api('/account/profile', { method: 'PATCH', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ firstName: $('profile-first').value, lastName: $('profile-last').value, phone: $('profile-phone').value }) })
          go('/dashboard/')
        } catch (err) { showError(err.message) }
      })
    }

    if (page === 'password-change') {
      const session = await requireSession()
      if (!session) return
      $('form-password-change').addEventListener('submit', async (e) => {
        e.preventDefault()
        try {
          await api('/auth/password/change', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ currentPassword: $('change-current').value, mfaCode: $('change-mfa').value.trim(), newPassword: $('change-new').value }) })
          go('/dashboard/')
        } catch (err) { showError(err.message) }
      })
    }

    if (page === 'authenticator') {
      const session = await requireSession()
      if (!session) return
      $('mfa-manage-status').textContent = session.user.mfaEnabled ? 'Authenticator is currently on.' : 'Authenticator is currently off.'
      $('mfa-resetup').addEventListener('click', () => {
        // The setup page itself will ask for the current password.
        // Nothing sensitive is passed through storage to get there.
        go('/mfa-setup/')
      })
      $('form-mfa-disable').addEventListener('submit', async (e) => {
        e.preventDefault()
        try {
          await api('/auth/mfa/disable', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ currentPassword: $('disable-current').value, mfaCode: $('disable-mfa').value.trim() }) })
          go('/dashboard/')
        } catch (err) { showError(err.message) }
      })
    }

    if (page === 'sessions') {
      const session = await requireSession()
      if (!session) return
      try {
        const data = await api('/account/sessions', { method: 'GET' })
        const list = $('session-list')
        list.innerHTML = ''
        data.sessions.forEach((s) => {
          const li = document.createElement('li')
          li.innerHTML = `<span>${s.current ? '<strong>This device</strong> · ' : ''}Created ${new Date(s.created_at).toLocaleString()} · Expires ${new Date(s.expires_at).toLocaleString()}${s.user_agent ? ' · ' + s.user_agent.slice(0, 60) : ''}</span>`
          if (!s.current) {
            const btn = document.createElement('button')
            btn.type = 'button'; btn.className = 'btn-secondary'; btn.textContent = 'Revoke'
            btn.addEventListener('click', async () => {
              try { await api('/account/sessions/revoke', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ sessionId: s.id }) }); li.remove() } catch (err) { showError(err.message) }
            })
            li.appendChild(btn)
          }
          list.appendChild(li)
        })
      } catch (err) { showError(err.message) }
    }

    if (page === 'recovery-regenerate') {
      const session = await requireSession()
      if (!session) return
      $('form-recovery-regen').addEventListener('submit', async (e) => {
        e.preventDefault()
        try {
          const data = await api('/auth/recovery-codes/regenerate', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ currentPassword: $('regen-current').value, mfaCode: $('regen-mfa').value.trim() }) })
          renderRecoveryCodes(data.recoveryCodes || [], $('regen-list'))
          $('regen-list').classList.remove('hidden')
          $('regen-download').classList.remove('hidden')
          $('regen-download').onclick = () => downloadCodes(data.recoveryCodes || [], 'kluzar-recovery-codes-new.txt')
          showInfo('New recovery codes generated. Old codes no longer work.')
        } catch (err) { showError(err.message) }
      })
    }

    if (page === 'expired') {
      renderChrome(false)
      $('expired-login').addEventListener('click', () => go('/login/'))
    }

    // Notice left by a previous page (e.g. after password reset).
    const notice = S.getItem('kluzar_notice')
    if (notice) { S.removeItem('kluzar_notice'); showInfo(notice) }
  })
})()
