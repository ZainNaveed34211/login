// Kluzar Accounts frontend. Plain JavaScript, no framework.
// The frontend never decides authentication by itself: every protected
// screen waits for GET /auth/session to confirm the session, and every
// Premium decision waits for GET /account/entitlements from the server.
// Session credentials live only in the server-set HttpOnly cookie — never
// in localStorage or sessionStorage. Temporary setup/challenge tokens live
// only in memory (this page's variables) and are lost on reload, by design.
(function () {
  'use strict'
  const API = window.KLUZAR_CONFIG.API_BASE_URL
  const PAYMENTS_URL = window.KLUZAR_CONFIG.PAYMENTS_URL
  const state = {
    email: '',
    passwordFailCount: 0,
    setupToken: null,
    challengeToken: null,
    recoveryToken: null,
    csrfToken: null,
    user: null,
    entitlement: null,
  }
  const $ = (id) => document.getElementById(id)
  function show(viewId) {
    document.querySelectorAll('.view').forEach((el) => el.classList.add('hidden'))
    const el = $(viewId)
    if (el) el.classList.remove('hidden')
    hideError()
  }
  function showError(msg) {
    const el = $('global-error')
    el.textContent = msg
    el.classList.remove('hidden')
  }
  function hideError() {
    $('global-error').classList.add('hidden')
    $('global-error').textContent = ''
  }
  function showInfo(msg) {
    const el = $('global-info')
    el.textContent = msg
    el.classList.remove('hidden')
    setTimeout(() => el.classList.add('hidden'), 8000)
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
  function setAuthedUI(authed) {
    $('nav-dashboard').classList.toggle('hidden', !authed)
    $('nav-logout').classList.toggle('hidden', !authed)
  }
  // --- Brand logo (exact main-page logo, from logo.js) ---
  if (window.KLUZAR_LOGO_URL) $('brand-logo').src = window.KLUZAR_LOGO_URL

  // --- Email entry ---
  $('form-email').addEventListener('submit', (e) => {
    e.preventDefault()
    state.email = $('email-input').value.trim()
    state.passwordFailCount = 0
    $('password-email-label').textContent = state.email
    show('view-password')
    $('password-input').focus()
  })
  $('back-to-email').addEventListener('click', () => { state.passwordFailCount = 0; show('view-email') })
  $('go-signup').addEventListener('click', () => show('view-signup'))
  $('back-to-login').addEventListener('click', () => show('view-email'))
  $('brand-home').addEventListener('click', (e) => { e.preventDefault(); show(state.user ? 'view-dashboard' : 'view-email') })
  $('nav-dashboard').addEventListener('click', () => loadDashboard())

  // --- Password entry: after 2 consecutive wrong passwords, back to email ---
  $('form-password').addEventListener('submit', async (e) => {
    e.preventDefault()
    const password = $('password-input').value
    try {
      const data = await api('/auth/login', { method: 'POST', body: JSON.stringify({ email: state.email, password }) })
      state.passwordFailCount = 0
      if (data.setupRequired) {
        state.setupToken = data.setupToken
        await startMfaSetup()
        return
      }
      if (data.mfaRequired) {
        state.challengeToken = data.challengeToken
        show('view-mfa-verify')
        return
      }
      state.user = data.user
      state.csrfToken = data.csrfToken
      await loadDashboard()
    } catch (err) {
      state.passwordFailCount += 1
      $('password-input').value = ''
      if (state.passwordFailCount >= 2) {
        // UI reset only — server-side abuse counters are NOT reset by this.
        state.passwordFailCount = 0
        showError('Too many incorrect attempts in this flow. Please start again from your email address.')
        show('view-email')
      } else {
        showError(err.message)
      }
    }
  })

  // --- Sign up ---
  $('form-signup').addEventListener('submit', async (e) => {
    e.preventDefault()
    const email = $('signup-email').value.trim()
    const password = $('signup-password').value
    const password2 = $('signup-password2').value
    if (password !== password2) { showError('Passwords do not match.'); return }
    try {
      const data = await api('/auth/register', { method: 'POST', body: JSON.stringify({ email, password }) })
      state.email = email
      state.setupToken = data.setupToken
      await startMfaSetup()
    } catch (err) { showError(err.message) }
  })

  async function startMfaSetup() {
    try {
      const data = await api('/auth/mfa/setup', { method: 'POST', body: JSON.stringify({ setupToken: state.setupToken }) })
      $('manual-key').textContent = data.manualKey
      // QR is rendered locally in the browser from the otpauth URL.
      // The secret is never sent to any external QR service.
      if (window.KluzarQRCode && window.KluzarQRCode.toDataURL) {
        $('qr-img').src = await window.KluzarQRCode.toDataURL(data.otpauthUrl, { width: 220, margin: 1 })
      } else {
        $('qr-img').alt = 'QR code unavailable — use the setup key below.'
      }
      if (data.setupToken) state.setupToken = data.setupToken
      show('view-mfa-setup')
    } catch (err) { showError(err.message) }
  }
  $('form-mfa-setup').addEventListener('submit', async (e) => {
    e.preventDefault()
    const form = $('form-mfa-setup')
    try {
      if (form.dataset.mode === 'res setup') {
        // Authenticated re-setup: verify via the session, no setup token.
        await api('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ code: $('mfa-setup-code').value.trim() }) })
        form.dataset.mode = ''
        showInfo('New authenticator activated.')
        await loadDashboard()
        return
      }
      const data = await api('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ setupToken: state.setupToken, code: $('mfa-setup-code').value.trim() }) })
      renderRecoveryCodes(data.recoveryCodes || [], $('recovery-list'))
      state.setupToken = null
      // Setup verify already issued a session (MFA succeeded). After the
      // user saves their codes, go straight to the dashboard, not back
      // through login with the same 30-second code.
      if (data.user) { state.user = data.user; state.csrfToken = data.csrfToken }
      show('view-recovery')
    } catch (err) { showError(err.message) }
  })
  function renderRecoveryCodes(codes, listEl) {
    listEl.innerHTML = ''
    codes.forEach((c) => { const li = document.createElement('li'); li.textContent = c; listEl.appendChild(li) })
    listEl.dataset.codes = JSON.stringify(codes)
  }
  function downloadCodes(listEl, filename) {
    const codes = JSON.parse(listEl.dataset.codes || '[]')
    const blob = new Blob(['Kluzar recovery codes — store these somewhere safe. Each code works once.\n\n' + codes.join('\n') + '\n'], { type: 'text/plain' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = filename
    a.click()
    URL.revokeObjectURL(a.href)
  }
  $('download-codes').addEventListener('click', () => downloadCodes($('recovery-list'), 'kluzar-recovery-codes.txt'))
  $('recovery-done').addEventListener('click', async () => {
    if (state.user) { await loadDashboard(); return }
    show('view-email'); showInfo('Your account is activated. Please sign in with your email, password and authenticator code.')
  })

  // --- MFA verify (login challenge) ---
  $('form-mfa-verify').addEventListener('submit', async (e) => {
    e.preventDefault()
    try {
      const data = await api('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ challengeToken: state.challengeToken, code: $('mfa-code').value.trim() }) })
      state.user = data.user
      state.csrfToken = data.csrfToken
      state.challengeToken = null
      await loadDashboard()
    } catch (err) { showError(err.message) }
  })

  // --- Forgot password ---
  function goForgot() {
    $('forgot-email').value = state.email || ''
    $('forgot-reset').classList.add('hidden')
    show('view-forgot')
  }
  $('go-forgot-1').addEventListener('click', goForgot)
  $('go-forgot-2').addEventListener('click', goForgot)
  $('form-forgot').addEventListener('submit', async (e) => {
    e.preventDefault()
    try {
      const data = await api('/auth/password/forgot', { method: 'POST', body: JSON.stringify({ email: $('forgot-email').value.trim(), code: $('forgot-code').value.trim() }) })
      if (data.recoveryToken) {
        state.recoveryToken = data.recoveryToken
        $('forgot-reset').classList.remove('hidden')
        showInfo('Recovery step verified. This recovery step is short-lived and single-use — set a new password now.')
      } else {
        showInfo(data.message || 'If an account exists, a recovery step is available.')
      }
    } catch (err) { showError(err.message) }
  })
  $('form-reset').addEventListener('submit', async (e) => {
    e.preventDefault()
    const p1 = $('reset-password').value
    const p2 = $('reset-password2').value
    if (p1 !== p2) { showError('Passwords do not match.'); return }
    try {
      await api('/auth/password/reset', { method: 'POST', body: JSON.stringify({ recoveryToken: state.recoveryToken, newPassword: p1 }) })
      state.recoveryToken = null
      show('view-email')
      showInfo('Password changed. Please sign in again with your new password and authenticator code.')
    } catch (err) { showError(err.message) }
  })

  // --- Dashboard + entitlements (server-verified only) ---
  async function loadDashboard() {
    try {
      const session = await api('/auth/session', { method: 'GET' })
      state.user = session.user
      state.csrfToken = session.csrfToken
      state.entitlement = session.entitlement
      setAuthedUI(true)
      $('dash-email').textContent = session.user.email
      $('dash-verified').textContent = session.user.emailVerified ? 'Email verified' : 'Email not yet verified (verification is not implemented in this phase)'
      $('dash-name').textContent = [session.user.firstName, session.user.lastName].filter(Boolean).join(' ') || '—'
      $('dash-phone').textContent = session.user.phone || '—'
      $('dash-mfa').textContent = session.user.mfaEnabled ? 'On' : 'Off'
      renderEntitlement(session.entitlement)
      show('view-dashboard')
    } catch (err) {
      setAuthedUI(false)
      if (err.status === 401) show('view-expired')
      else showError(err.message)
    }
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
  $('entitlement-retry').addEventListener('click', loadDashboard)
  $('expired-login').addEventListener('click', () => show('view-email'))

  async function logout() {
    try { await api('/auth/logout', { method: 'POST', body: JSON.stringify({}) }) } catch { /* ignore */ }
    state.user = null; state.csrfToken = null; setAuthedUI(false); show('view-email')
  }
  $('nav-logout').addEventListener('click', logout)
  $('dash-logout-all').addEventListener('click', async () => {
    try {
      await api('/auth/logout-all', { method: 'POST', headers: { 'X-CSRF-Token': state.csrfToken || '' }, body: JSON.stringify({}) })
    } catch (err) { showError(err.message); return }
    state.user = null; state.csrfToken = null; setAuthedUI(false); show('view-email'); showInfo('Logged out of all devices.')
  })

  // --- Profile ---
  $('go-profile').addEventListener('click', () => {
    $('profile-first').value = state.user.firstName || ''
    $('profile-last').value = state.user.lastName || ''
    $('profile-phone').value = state.user.phone || ''
    show('view-profile')
  })
  $('profile-back').addEventListener('click', () => loadDashboard())
  $('form-profile').addEventListener('submit', async (e) => {
    e.preventDefault()
    try {
      const data = await api('/account/profile', {
        method: 'PATCH',
        headers: { 'X-CSRF-Token': state.csrfToken || '' },
        body: JSON.stringify({ firstName: $('profile-first').value, lastName: $('profile-last').value, phone: $('profile-phone').value }),
      })
      state.user = data.user
      showInfo('Profile saved.')
      await loadDashboard()
    } catch (err) { showError(err.message) }
  })

  // --- Password change ---
  $('go-password-change').addEventListener('click', () => show('view-password-change'))
  $('password-change-back').addEventListener('click', () => loadDashboard())
  $('form-password-change').addEventListener('submit', async (e) => {
    e.preventDefault()
    try {
      const data = await api('/auth/password/change', {
        method: 'POST',
        headers: { 'X-CSRF-Token': state.csrfToken || '' },
        body: JSON.stringify({ currentPassword: $('change-current').value, mfaCode: $('change-mfa').value.trim(), newPassword: $('change-new').value }),
      })
      state.csrfToken = data.csrfToken
      showInfo('Password changed. Your other sessions were signed out.')
      await loadDashboard()
    } catch (err) { showError(err.message) }
  })

  // --- MFA management ---
  $('go-mfa-manage').addEventListener('click', () => {
    $('mfa-manage-status').textContent = state.user.mfaEnabled ? 'Authenticator is currently on.' : 'Authenticator is currently off.'
    show('view-mfa-manage')
  })
  $('mfa-manage-back').addEventListener('click', () => loadDashboard())
  $('mfa-resetup').addEventListener('click', async () => {
    // Re-setup requires the current password (asked on the MFA setup
    // screen via a prompt-free flow: use the disable form's password field
    // value if present, otherwise ask the user to enter it on the setup
    // screen. For simplicity, start setup with a session-based request
    // that the server validates against the current password below.
    const currentPassword = $('disable-current').value
    if (!currentPassword) { showError('Enter your current password first, then choose Set up a new authenticator.'); return }
    try {
      const data = await api('/auth/mfa/setup', { method: 'POST', body: JSON.stringify({ currentPassword }) })
      $('manual-key').textContent = data.manualKey
      if (window.KluzarQRCode && window.KluzarQRCode.toDataURL) {
        $('qr-img').src = await window.KluzarQRCode.toDataURL(data.otpauthUrl, { width: 220, margin: 1 })
      }
      // Re-setup verify uses the session-based path (no setupToken).
      state.setupToken = null
      show('view-mfa-setup')
      // Swap the setup form handler to session mode for this one flow:
      $('form-mfa-setup').dataset.mode = 'res setup'
    } catch (err) { showError(err.message) }
  })
  $('form-mfa-disable').addEventListener('submit', async (e) => {
    e.preventDefault()
    try {
      const data = await api('/auth/mfa/disable', {
        method: 'POST',
        headers: { 'X-CSRF-Token': state.csrfToken || '' },
        body: JSON.stringify({ currentPassword: $('disable-current').value, mfaCode: $('disable-mfa').value.trim() }),
      })
      state.csrfToken = data.csrfToken
      showInfo('Authenticator disabled. Your recovery codes were removed.')
      await loadDashboard()
    } catch (err) { showError(err.message) }
  })

  // --- Sessions ---
  $('go-sessions').addEventListener('click', async () => {
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
            try {
              await api('/account/sessions/revoke', { method: 'POST', headers: { 'X-CSRF-Token': state.csrfToken || '' }, body: JSON.stringify({ sessionId: s.id }) })
              li.remove()
            } catch (err) { showError(err.message) }
          })
          li.appendChild(btn)
        }
        list.appendChild(li)
      })
      show('view-sessions')
    } catch (err) { showError(err.message) }
  })
  $('sessions-back').addEventListener('click', () => loadDashboard())

  // --- Recovery regeneration ---
  $('go-recovery-regen').addEventListener('click', () => show('view-recovery-regen'))
  $('regen-back').addEventListener('click', () => loadDashboard())
  $('form-recovery-regen').addEventListener('submit', async (e) => {
    e.preventDefault()
    try {
      const data = await api('/auth/recovery-codes/regenerate', {
        method: 'POST',
        headers: { 'X-CSRF-Token': state.csrfToken || '' },
        body: JSON.stringify({ currentPassword: $('regen-current').value, mfaCode: $('regen-mfa').value.trim() }),
      })
      renderRecoveryCodes(data.recoveryCodes || [], $('regen-list'))
      $('regen-list').classList.remove('hidden')
      $('regen-download').classList.remove('hidden')
      showInfo('New recovery codes generated. Old codes no longer work.')
    } catch (err) { showError(err.message) }
  })
  $('regen-download').addEventListener('click', () => downloadCodes($('regen-list'), 'kluzar-recovery-codes-new.txt'))

  // --- Initial: if a session cookie exists, try to load the dashboard ---
  ;(async () => {
    try {
      const session = await api('/auth/session', { method: 'GET' })
      if (session.authenticated) await loadDashboard()
    } catch { /* not logged in — stay on email entry */ }
  })()
})()
