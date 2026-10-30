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
  // Client-side checks only - the Worker re-checks everything server-side.
  // Never send obviously invalid input to the API, and never render
  // user input as HTML (see sessions list below).
  const isEmailFormat = (v) => typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.trim()) && v.length <= 254
  const isPasswordOk = (v) => typeof v === 'string' && v.length >= 12 && v.length <= 128 && /[a-z]/.test(v) && /[A-Z]/.test(v) && /[0-9]/.test(v) && /[^A-Za-z0-9]/.test(v)
  const isCodeFormat = (v) => /^\d{6}$/.test(String(v || '').trim())
  const isNameOk = (v) => v === '' || (typeof v === 'string' && v.length <= 100 && !/[<>&\u0000-\u001F\u007F]/.test(v))
  const isPhoneOk = (v) => v === '' || (typeof v === 'string' && v.length <= 50 && /[0-9]/.test(v) && /^[0-9+\s().-]+$/.test(v))
  const $ = (id) => document.getElementById(id)
  // Safe setters: a missing element must never abort a whole page. This
  // matters when a browser serves a new HTML file with a cached older JS
  // file (or vice versa) — one absent element used to throw here and stop
  // the dashboard before the subscription section could render.
  const setText = (id, value) => { const el = $(id); if (el) el.textContent = value }
  const setHidden = (id, hidden) => { const el = $(id); if (el) el.classList.toggle('hidden', hidden) }
  // Return-to-origin support (for Kluzar subdomains such as SEO):
  // a ?next= value is honoured ONLY at the post-login landing step, and
  // ONLY when it is https://kluzar.com or https://*.kluzar.com — never
  // accounts.kluzar.com itself (that would loop), never another host,
  // never http, never a URL with credentials. Anything else falls back
  // to /dashboard/. This is not an open redirect: the allowlist above
  // is the whole rule, and no other destination can pass it.
  function validReturnTarget() {
    try {
      const raw = new URLSearchParams(window.location.search).get('next')
      if (!raw || raw.length > 2048) return null
      const u = new URL(raw)
      if (u.protocol !== 'https:' || u.username || u.password) return null
      const h = u.hostname.toLowerCase()
      if (h === 'kluzar.com' || (h.endsWith('.kluzar.com') && h !== 'accounts.kluzar.com')) return u.toString()
      return null
    } catch { return null }
  }
  const go = (page) => {
    // Post-login landing: return to the Kluzar subdomain the user came
    // from, when one was requested and passed validation above.
    if (page === '/dashboard/') {
      const target = validReturnTarget()
      if (target) { window.location.href = target; return }
    }
    // Preserve a requested return target across internal auth steps
    // (email -> password -> code / MFA setup), so it is still present
    // at the landing step. Plain links (<a href>) are untouched.
    if (typeof page === 'string' && page.startsWith('/') && !page.includes('next=')) {
      const target = validReturnTarget()
      if (target) {
        const sep = page.includes('?') ? '&' : '?'
        window.location.href = page + sep + 'next=' + encodeURIComponent(target)
        return
      }
    }
    window.location.href = page
  }
  // Direct dashboard landing for already-logged-in users: unlike go(),
  // this NEVER honours ?next=. The SEO account button links everyone to
  // /login/?next=<seo>, and the accounts app itself decides from the
  // server-verified session: logged-out users log in and then return
  // (post-login go() honours next), while users who already have a
  // session go straight to their dashboard through this helper.
  const goDashboard = () => { window.location.href = '/dashboard/' }
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
    // Server now requires the session CSRF token on logout (see
    // handlers.js). Fetch it fresh from GET /auth/session first; if
    // that fails there is no session to revoke, so just clear locally.
    // Old Worker versions ignore the extra header, so deploying this
    // frontend BEFORE the Worker change is safe; deploying the Worker
    // first would leave the server session alive while the browser
    // appears logged out.
    try {
      const s = await api('/auth/session', { method: 'GET' })
      if (s.csrfToken) await api('/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': s.csrfToken }, body: JSON.stringify({}) })
    } catch { /* ignore: local clear + redirect below still runs */ }
    S.clear()
    go('/login/')
  }
  // FAIL CLOSED: a protected page must NEVER stay open when the session
  // cannot be verified. 401, network failure, DNS failure, Worker not
  // deployed yet, 500 - every failure means the same thing here: go back
  // to /login/. Showing an error and staying on the page was the bug
  // that let /dashboard/ open without a login.
  async function redirectIfAuthed() {
    try {
      const s = await api('/auth/session', { method: 'GET' })
      // Never trust a client-editable flag alone: api() already throws on
      // any non-2xx status, so this runs only on a server-verified 200
      // response, and the dashboard itself re-verifies the session
      // server-side before showing any data. Editing `authenticated`
      // in DevTools or a proxy can at most show an empty shell locally —
      // it can never make the server return another account's data.
      if (s.ok && s.authenticated) { goDashboard(); return true }
    } catch { /* not logged in - continue with the page's own guard */ }
    return false
  }
  // Protected pages: if the session dies mid-page (e.g. a form submit
  // after expiry), go back to /login/ instead of showing a bare error.
  function handleProtectedError(err) {
    if (err && err.status === 401) { S.setItem('kluzar_notice', 'Please sign in to continue.'); go('/login/'); return true }
    showError(err.message)
    return false
  }
  async function requireSession() {
    try {
      const session = await api('/auth/session', { method: 'GET' })
      renderChrome(true)
      document.body.style.visibility = 'visible'
      return session
    } catch (err) {
      renderChrome(false)
      S.setItem('kluzar_notice', 'Please sign in to continue.')
      go('/login/')
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
    setHidden('entitlement-loading', true)
    if (!ent) {
      setHidden('entitlement-error', false)
      setHidden('entitlement-content', true)
      return
    }
    setHidden('entitlement-error', true)
    setHidden('entitlement-content', false)
    setText('ent-plan', ent.plan)
    setText('ent-status', ent.status)
    setText('ent-note', ent.premium
      ? 'You already have Premium access. Get Premium is hidden because your plan already grants it.'
      : 'You are on the free plan. Get Premium to unlock deeper scans, premium findings and branded reports.')
    const btn = $('get-premium-btn')
    // Show only when server-verified Free, hide when paid. Loading/error
    // states above never assume Free or paid.
    if (btn) { btn.classList.toggle('hidden', !!ent.premium); btn.href = PAYMENTS_URL }
  }
  async function loadDashboard() {
    const session = await requireSession()
    if (!session) return
    setText('dash-email', session.user.email)
    setText('dash-name', [session.user.firstName, session.user.lastName].filter(Boolean).join(' ') || '—')
    setText('dash-phone', session.user.phone || '—')
    setText('dash-mfa', session.user.mfaEnabled ? 'On' : 'Off')
    renderEntitlement(session.entitlement)
    const logoutAll = $('dash-logout-all')
    if (logoutAll) logoutAll.addEventListener('click', async () => {
      try {
        await api('/auth/logout-all', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({}) })
      } catch (err) { handleProtectedError(err); return }
      S.clear()
      go('/login/')
    })
    const retry = $('entitlement-retry')
    if (retry) retry.addEventListener('click', () => window.location.reload())
  }
  // Password visibility toggles: every page marks its password inputs with
  // a small eye button (class pw-toggle, data-for = input id). Toggling only
  // changes the input type between password and text on this page — it never
  // stores, copies or sends the password anywhere, and the button is
  // type="button" so it can never submit a form.
  const EYE_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>'
  const EYE_OFF_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 6.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
  function setupPasswordToggles() {
    document.querySelectorAll('.pw-toggle').forEach((btn) => {
      const input = document.getElementById(btn.dataset.for)
      if (!input) return
      btn.addEventListener('click', () => {
        const showing = input.type === 'text'
        input.type = showing ? 'password' : 'text'
        btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password')
        btn.setAttribute('aria-pressed', showing ? 'false' : 'true')
        btn.innerHTML = showing ? EYE_SVG : EYE_OFF_SVG
        input.focus()
      })
    })
  }
  // Page dispatch — document.body.dataset.page is set in each page's HTML.
  const page = document.body ? document.body.dataset.page : ''
  document.addEventListener('DOMContentLoaded', async () => {
    setupPasswordToggles()
    // Pages that need no session render chrome unauthenticated by default.
    if (!['dashboard', 'profile', 'password-change', 'authenticator', 'sessions', 'recovery-regenerate'].includes(page)) renderChrome(false)

    if (page === 'login-email') {
      $('form-email').addEventListener('submit', (e) => {
        e.preventDefault()
        const email0 = $('email-input').value.trim()
        if (!isEmailFormat(email0)) { showError('Please enter a valid email address.'); return }
        S.setItem('kluzar_email', email0)
        S.setItem('kluzar_password_failures', '0')
        go('/login/password/')
      })
      $('go-signup').addEventListener('click', () => go('/signup/'))
      $('go-forgot-1').addEventListener('click', () => go('/forget-password/'))
      // If already logged in, go straight to dashboard.
      try { const s = await api('/auth/session', { method: 'GET' }); if (s.authenticated) goDashboard() } catch { /* stay */ }
    }

    if (page === 'login-password') {
      if (await redirectIfAuthed()) return
      const email = S.getItem('kluzar_email') || ''
      if (!isEmailFormat(email)) { S.removeItem('kluzar_email'); go('/login/'); return }
      $('password-email-label').textContent = email
      $('back-to-email').addEventListener('click', () => go('/login/'))
      $('go-forgot-2').addEventListener('click', () => go('/forget-password/'))
      $('form-password').addEventListener('submit', async (e) => {
        e.preventDefault()
        try {
          const data = await api('/auth/login', { method: 'POST', body: JSON.stringify({ email, password: $('password-input').value }) })
          S.setItem('kluzar_password_failures', '0')
          S.removeItem('kluzar_email')
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
            S.removeItem('kluzar_email')
            S.setItem('kluzar_password_failures', '0')
            S.setItem('kluzar_notice', 'Too many incorrect attempts in this flow. Please start again from your email address.')
            go('/login/')
          } else showError(err.message)
        }
      })
    }

    if (page === 'signup') {
      if (await redirectIfAuthed()) return
      $('back-to-login').addEventListener('click', () => go('/login/'))
      $('form-signup').addEventListener('submit', async (e) => {
        e.preventDefault()
        const email = $('signup-email').value.trim()
        const password = $('signup-password').value
        if (!isEmailFormat(email)) { showError('Please enter a valid email address.'); return }
        if (!isPasswordOk(password)) { showError('Password must be 12 to 128 characters and include an uppercase letter, a lowercase letter, a number, and a symbol.'); return }
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
            const data = await api('/auth/mfa/setup', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ currentPassword: $('setup-current-password').value }) })
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
        if (!isCodeFormat($('mfa-setup-code').value)) { showError('Enter the 6-digit authenticator code.'); return }
        try {
          if (sessionMode) {
            // Authenticated re-setup verify now requires CSRF on the
            // server. The session object from the setup step is not in
            // scope here, so fetch a fresh token first (same pattern
            // as logout()).
            const s = await api('/auth/session', { method: 'GET' })
            await api('/auth/mfa/verify', { method: 'POST', headers: { 'X-CSRF-Token': s.csrfToken }, body: JSON.stringify({ code: $('mfa-setup-code').value.trim() }) })
            goDashboard()
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
      if (await redirectIfAuthed()) return
      const challengeToken = S.getItem('kluzar_challenge_token')
      if (!challengeToken) { go('/login/'); return }
      $('form-mfa-verify').addEventListener('submit', async (e) => {
        e.preventDefault()
        if (!isCodeFormat($('mfa-code').value)) { showError('Enter the 6-digit authenticator code.'); return }
        try {
          await api('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ challengeToken, code: $('mfa-code').value.trim() }) })
          S.removeItem('kluzar_challenge_token')
          go('/dashboard/')
        } catch (err) { showError(err.message) }
      })
    }

    if (page === 'recovery-codes') {
      const codes = JSON.parse(S.getItem('kluzar_recovery_codes') || '[]')
      if (!codes.length) {
        try { const s = await api('/auth/session', { method: 'GET' }); if (s.authenticated) go('/dashboard/'); else go('/login/') } catch { go('/login/') }
        return
      }
      renderRecoveryCodes(codes, $('recovery-list'))
      $('download-codes').addEventListener('click', () => downloadCodes(codes, 'kluzar-recovery-codes.txt'))
      $('recovery-done').addEventListener('click', () => { S.removeItem('kluzar_recovery_codes'); go('/dashboard/') })
    }

    if (page === 'forget-password') {
      try { const s = await api('/auth/session', { method: 'GET' }); if (s.authenticated) renderChrome(true) } catch { /* stay unauthenticated */ }
      $('forgot-email').value = S.getItem('kluzar_email') || ''
      $('form-forgot').addEventListener('submit', async (e) => {
        e.preventDefault()
        if (!isEmailFormat($('forgot-email').value)) { showError('Please enter a valid email address.'); return }
        if (!isCodeFormat($('forgot-code').value)) { showError('Enter the 6-digit authenticator or recovery code.'); return }
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
      try { const s = await api('/auth/session', { method: 'GET' }); if (s.authenticated) renderChrome(true) } catch { /* stay unauthenticated */ }
      const recoveryToken = S.getItem('kluzar_recovery_token')
      if (!recoveryToken) { go('/forget-password/'); return }
      $('form-reset').addEventListener('submit', async (e) => {
        e.preventDefault()
        if (!isPasswordOk($('reset-password').value)) { showError('Password must be 12 to 128 characters and include an uppercase letter, a lowercase letter, a number, and a symbol.'); return }
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
        if (!isNameOk($('profile-first').value) || !isNameOk($('profile-last').value) || !isPhoneOk($('profile-phone').value)) { showError('Profile details are invalid. Names must not contain <, > or & and phone must contain only digits, +, spaces, -, ( ) or .'); return }
        try {
          await api('/account/profile', { method: 'PATCH', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ firstName: $('profile-first').value, lastName: $('profile-last').value, phone: $('profile-phone').value }) })
          go('/dashboard/')
        } catch (err) { handleProtectedError(err) }
      })
    }

    if (page === 'password-change') {
      const session = await requireSession()
      if (!session) return
      $('form-password-change').addEventListener('submit', async (e) => {
        e.preventDefault()
        if (!isCodeFormat($('change-mfa').value)) { showError('Enter the 6-digit authenticator code.'); return }
        if (!isPasswordOk($('change-new').value)) { showError('Password must be 12 to 128 characters and include an uppercase letter, a lowercase letter, a number, and a symbol.'); return }
        try {
          await api('/auth/password/change', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ currentPassword: $('change-current').value, mfaCode: $('change-mfa').value.trim(), newPassword: $('change-new').value }) })
          go('/dashboard/')
        } catch (err) { handleProtectedError(err) }
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
        if (!isCodeFormat($('disable-mfa').value)) { showError('Enter the 6-digit authenticator code.'); return }
        try {
          await api('/auth/mfa/disable', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ currentPassword: $('disable-current').value, mfaCode: $('disable-mfa').value.trim() }) })
          go('/dashboard/')
        } catch (err) { handleProtectedError(err) }
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
          const span = document.createElement('span')
          // textContent only: user_agent comes from the browser and can
          // contain markup. It must never be inserted as HTML.
          span.textContent = (s.current ? 'This device · ' : '') + 'Created ' + new Date(s.created_at).toLocaleString() + ' · Expires ' + new Date(s.expires_at).toLocaleString() + (s.user_agent ? ' · ' + s.user_agent.slice(0, 60) : '')
          li.appendChild(span)
          if (!s.current) {
            const btn = document.createElement('button')
            btn.type = 'button'; btn.className = 'btn-secondary'; btn.textContent = 'Revoke'
            btn.addEventListener('click', async () => {
              try { await api('/account/sessions/revoke', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ sessionId: s.id }) }); li.remove() } catch (err) { handleProtectedError(err) }
            })
            li.appendChild(btn)
          }
          list.appendChild(li)
        })
      } catch (err) { handleProtectedError(err) }
    }

    if (page === 'recovery-regenerate') {
      const session = await requireSession()
      if (!session) return
      $('form-recovery-regen').addEventListener('submit', async (e) => {
        e.preventDefault()
        if (!isCodeFormat($('regen-mfa').value)) { showError('Enter the 6-digit authenticator code.'); return }
        try {
          const data = await api('/auth/recovery-codes/regenerate', { method: 'POST', headers: { 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ currentPassword: $('regen-current').value, mfaCode: $('regen-mfa').value.trim() }) })
          renderRecoveryCodes(data.recoveryCodes || [], $('regen-list'))
          $('regen-list').classList.remove('hidden')
          $('regen-download').classList.remove('hidden')
          $('regen-download').onclick = () => downloadCodes(data.recoveryCodes || [], 'kluzar-recovery-codes-new.txt')
          showInfo('New recovery codes generated. Old codes no longer work.')
        } catch (err) { handleProtectedError(err) }
      })
    }

    if (page === 'expired') {
      if (await redirectIfAuthed()) return
      renderChrome(false)
      $('expired-login').addEventListener('click', () => go('/login/'))
    }

    // Notice left by a previous page (e.g. after password reset).
    const notice = S.getItem('kluzar_notice')
    if (notice) { S.removeItem('kluzar_notice'); showInfo(notice) }
  })
})()
