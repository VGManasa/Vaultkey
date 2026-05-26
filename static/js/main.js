// main.js — VaultKey shared utilities
// Loaded on every page via base.html

// ── Password visibility toggle ───────────────────────────────
function togglePassword(id) {
    const input = document.getElementById(id);
    input.type = input.type === 'password' ? 'text' : 'password';
}

// ── Cryptographically secure password generator ──────────────
async function generatePassword() {
    let length = 16;
    try {
        const res  = await fetch('/api/accounts');
        const data = await res.json();
        const uid  = data.active_user;
        const key  = `vk_prefs_${uid}`;
        const saved = localStorage.getItem(key);
        if (saved) {
            const prefs = JSON.parse(saved);
            if (prefs.pwLength) length = parseInt(prefs.pwLength, 10);
        }
    } catch (_) {}

    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    let password = '';
    for (let i = 0; i < length; i++) {
        password += chars[array[i] % chars.length];
    }
    document.getElementById('entry-password').value = password;
    document.getElementById('entry-password').dispatchEvent(new Event('input'));
}

// ── Logout ────────────────────────────────────────────────────
async function logout() {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login';
}

// ── Sidebar toggle (mobile) ───────────────────────────────────
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    sidebar.classList.toggle('open');
    if (overlay) overlay.classList.toggle('active');
    document.body.classList.toggle('sidebar-open');
}


// ═════════════════════════════════════════════════════════════
// Vault Lock System
// ─────────────────────────────────────────────────────────────
// The server returns HTTP 423 when a vault-protected endpoint is
// called while the vault is locked. The frontend catches this,
// shows an unlock prompt, and retries the action after success.
// ═════════════════════════════════════════════════════════════

let _vaultLockPoller    = null;
let _vaultUnlockResolve = null;
let _lockOverlayVisible = false;
let _lockOverlayMode    = 'password'; // 'password' | 'set-password'

const VAULT_POLL_INTERVAL = 30_000;

// ── Start polling vault status ────────────────────────────────
function startVaultLockPoller() {
    if (_vaultLockPoller) clearInterval(_vaultLockPoller);

    _vaultLockPoller = setInterval(async () => {
        try {
            const res  = await fetch('/api/vault/status');
            if (!res.ok) return;
            const data = await res.json();

            if (data.locked && !_lockOverlayVisible) {
                _lockOverlayMode = data.has_password ? 'password' : 'set-password';
                _showVaultLockOverlay(_lockOverlayMode);
            }
        } catch (_) {}
    }, VAULT_POLL_INTERVAL);
}

// ── Stop polling ──────────────────────────────────────────────
function stopVaultLockPoller() {
    if (_vaultLockPoller) {
        clearInterval(_vaultLockPoller);
        _vaultLockPoller = null;
    }
}

// ── Show the lock overlay ─────────────────────────────────────
// mode: 'password'     — existing master password prompt
//       'set-password' — Google user who hasn't set a master password
function _showVaultLockOverlay(mode) {
    if (_lockOverlayVisible) return;
    _lockOverlayVisible = true;
    _lockOverlayMode    = mode || 'password';

    const isSetPassword = _lockOverlayMode === 'set-password';

    const overlay = document.createElement('div');
    overlay.id    = 'vault-lock-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', isSetPassword ? 'Set master password' : 'Vault locked');
    overlay.style.cssText = [
        'position:fixed',
        'inset:0',
        'background:rgba(10,12,16,0.93)',
        'backdrop-filter:blur(6px)',
        '-webkit-backdrop-filter:blur(6px)',
        'z-index:99999',
        'display:flex',
        'align-items:center',
        'justify-content:center',
        'padding:1rem',
        'animation:fadeInOverlay 0.25s ease',
    ].join(';');

    const headingText = isSetPassword ? 'Set a Master Password' : 'Vault Locked';
    const subText = isSetPassword
        ? 'You signed in with Google. Set a master password to encrypt and protect your vault entries.'
        : 'Your vault locked due to inactivity.<br>Enter your master password to continue.';
    const btnLabel = isSetPassword ? 'Set Password &amp; Unlock' : 'Unlock Vault';

    overlay.innerHTML = `
        <style>
          @keyframes fadeInOverlay { from { opacity:0; } to { opacity:1; } }
          @keyframes lockCardSlide {
            from { opacity:0; transform:translateY(18px) scale(0.97); }
            to   { opacity:1; transform:translateY(0) scale(1); }
          }
          #vault-lock-card { animation: lockCardSlide 0.3s cubic-bezier(0.22,1,0.36,1); }
          .vl-field-label {
            font-size:0.8125rem; font-weight:600;
            color:var(--text2); text-transform:uppercase;
            letter-spacing:0.06em; display:block; margin-bottom:0.4rem;
          }
          .vl-info-box {
            display:flex; align-items:flex-start; gap:0.6rem;
            background:rgba(79,142,247,0.08);
            border:1px solid rgba(79,142,247,0.25);
            border-radius:var(--radius-sm);
            padding:0.75rem 1rem;
            font-size:0.8125rem; color:var(--text2); line-height:1.6;
            margin-bottom:1rem;
          }
          .vl-info-box svg { flex-shrink:0; margin-top:2px; }
          .vl-strength-bar {
            display:flex; gap:4px; margin-top:0.5rem;
          }
          .vl-strength-block {
            flex:1; height:4px; border-radius:2px;
            background:var(--border2); transition:background 0.3s;
          }
        </style>

        <div id="vault-lock-card"
             style="background:var(--bg2);
                    border:1px solid var(--border2);
                    border-radius:var(--radius);
                    padding:2.5rem 2rem;
                    width:100%; max-width:400px;
                    box-shadow:var(--shadow);">

          <div style="width:64px;height:64px;border-radius:50%;
                      background:var(--accent-dim);
                      border:1px solid rgba(200,240,96,0.25);
                      color:var(--accent);
                      display:flex;align-items:center;justify-content:center;
                      margin:0 auto 1.5rem;">
            ${isSetPassword
                ? `<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                     <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                     <line x1="12" y1="8" x2="12" y2="12"/>
                     <line x1="12" y1="16" x2="12.01" y2="16"/>
                   </svg>`
                : `<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                     <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                     <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                   </svg>`}
          </div>

          <div style="text-align:center;margin-bottom:1.75rem;">
            <h2 style="font-size:1.375rem;font-weight:700;color:var(--text);margin:0 0 0.35rem;">${headingText}</h2>
            <p style="color:var(--text2);font-size:0.875rem;margin:0;line-height:1.6;">${subText}</p>
          </div>

          <div id="vault-lock-error"
               style="display:none;background:var(--red-dim);
                      border:1px solid rgba(255,95,109,0.3);
                      color:var(--red);border-radius:var(--radius-sm);
                      padding:0.6rem 0.9rem;font-size:0.8125rem;
                      margin-bottom:1rem;"></div>

          ${isSetPassword ? `
          <div class="vl-info-box">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            <span>This password encrypts your vault. It is separate from your Google account and <strong style="color:var(--text);">cannot be recovered</strong> if lost.</span>
          </div>
          ` : ''}

          <div style="margin-bottom:${isSetPassword ? '0.75rem' : '1rem'};">
            <label class="vl-field-label">
              ${isSetPassword ? 'New Master Password' : 'Master Password'}
            </label>
            <div style="position:relative;">
              <input type="password"
                     id="vault-unlock-password"
                     class="field-input"
                     placeholder="${isSetPassword ? 'Minimum 8 characters' : 'Enter your master password'}"
                     autocomplete="${isSetPassword ? 'new-password' : 'current-password'}"
                     style="padding-right:2.8rem;width:100%;"/>
              <button type="button" class="toggle-pw"
                      onclick="togglePassword('vault-unlock-password')"
                      style="position:absolute;right:0.7rem;top:50%;transform:translateY(-50%);">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
              </button>
            </div>
            ${isSetPassword ? `
            <div class="vl-strength-bar" id="vl-sb-wrap">
              <div class="vl-strength-block" id="vl-sb-1"></div>
              <div class="vl-strength-block" id="vl-sb-2"></div>
              <div class="vl-strength-block" id="vl-sb-3"></div>
              <div class="vl-strength-block" id="vl-sb-4"></div>
            </div>
            <span id="vl-strength-label" style="font-size:0.75rem;font-family:var(--mono);display:block;margin-top:0.2rem;"></span>
            ` : ''}
          </div>

          ${isSetPassword ? `
          <div style="margin-bottom:1rem;">
            <label class="vl-field-label">Confirm Master Password</label>
            <div style="position:relative;">
              <input type="password"
                     id="vault-unlock-confirm"
                     class="field-input"
                     placeholder="Repeat password"
                     autocomplete="new-password"
                     style="padding-right:2.8rem;width:100%;"/>
              <button type="button" class="toggle-pw"
                      onclick="togglePassword('vault-unlock-confirm')"
                      style="position:absolute;right:0.7rem;top:50%;transform:translateY(-50%);">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
              </button>
            </div>
          </div>
          ` : ''}

          <button id="vault-unlock-btn"
                  class="btn-primary-full"
                  onclick="vaultUnlockSubmit()"
                  style="margin-top:0;">
            <span class="btn-text">${btnLabel}</span>
            <span class="btn-loader d-none"></span>
          </button>

          <p style="text-align:center;margin-top:1.25rem;font-size:0.8125rem;color:var(--text3);">
            ${isSetPassword
                ? `Want to do this later? <a href="/logout" style="color:var(--accent);text-decoration:none;font-weight:600;">Sign out</a>`
                : `Not you? <a href="/logout" style="color:var(--accent);text-decoration:none;font-weight:600;">Sign out</a>`}
          </p>
        </div>
    `;

    document.body.appendChild(overlay);

    const pwInput      = document.getElementById('vault-unlock-password');
    const confirmInput = document.getElementById('vault-unlock-confirm');

    pwInput.focus();

    // Strength meter for set-password mode
    if (isSetPassword) {
        const colors = ['', '#ff5f6d', '#f0a060', '#4f8ef7', '#c8f060'];
        const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
        pwInput.addEventListener('input', function () {
            const val = this.value;
            let score = 0;
            if (val.length >= 8)           score++;
            if (/[A-Z]/.test(val))         score++;
            if (/[0-9]/.test(val))         score++;
            if (/[^A-Za-z0-9]/.test(val))  score++;
            for (let i = 1; i <= 4; i++) {
                const block = document.getElementById(`vl-sb-${i}`);
                if (block) block.style.background = i <= score ? colors[score] : 'var(--border2)';
            }
            const lbl = document.getElementById('vl-strength-label');
            if (lbl) {
                lbl.textContent = val.length ? (labels[score] || '') : '';
                lbl.style.color = colors[score] || 'var(--text3)';
            }
        });
    }

    // Enter key handling
    pwInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            if (isSetPassword && confirmInput) confirmInput.focus();
            else vaultUnlockSubmit();
        }
    });
    if (confirmInput) {
        confirmInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') vaultUnlockSubmit();
        });
    }
}

// ── Overlay submit handler ────────────────────────────────────
async function vaultUnlockSubmit() {
    const password  = document.getElementById('vault-unlock-password').value;
    const confirmEl = document.getElementById('vault-unlock-confirm');
    const btn       = document.getElementById('vault-unlock-btn');
    const errEl     = document.getElementById('vault-lock-error');
    const isSetPw   = _lockOverlayMode === 'set-password';

    if (!password) {
        errEl.textContent   = 'Please enter your master password.';
        errEl.style.display = 'block';
        return;
    }

    if (isSetPw) {
        if (password.length < 8) {
            errEl.textContent   = 'Password must be at least 8 characters.';
            errEl.style.display = 'block';
            return;
        }
        const confirm = confirmEl ? confirmEl.value : '';
        if (password !== confirm) {
            errEl.textContent   = 'Passwords do not match.';
            errEl.style.display = 'block';
            return;
        }
    }

    btn.disabled = true;
    const textEl   = btn.querySelector('.btn-text');
    const loaderEl = btn.querySelector('.btn-loader');
    if (textEl)   textEl.classList.add('d-none');
    if (loaderEl) loaderEl.classList.remove('d-none');
    errEl.style.display = 'none';

    try {
        // Google users setting password first time → change-password endpoint
        // Existing users → unlock endpoint directly
        const endpoint = isSetPw ? '/api/profile/change-password' : '/api/vault/unlock';
        const body     = isSetPw ? { new_password: password } : { password };

        const res  = await fetch(endpoint, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(body)
        });
        const data = await res.json();

        if (res.ok) {
            // After Google user sets password, also unlock the vault in session
            if (isSetPw) {
                await fetch('/api/vault/unlock', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    JSON.stringify({ password })
                });
            }

            _dismissLockOverlay();

            if (_vaultUnlockResolve) {
                _vaultUnlockResolve(true);
                _vaultUnlockResolve = null;
            }

            startVaultLockPoller();

            if (isSetPw && typeof showToast === 'function') {
                showToast('Master password set — vault unlocked', 'success');
            }
        } else {
            btn.disabled = false;
            if (textEl)   textEl.classList.remove('d-none');
            if (loaderEl) loaderEl.classList.add('d-none');

            // Server says this account needs a password set, not unlocked
            if (data.needs_password && !isSetPw) {
                _dismissLockOverlay();
                _lockOverlayVisible = false;
                _showVaultLockOverlay('set-password');
                return;
            }

            errEl.textContent   = data.error || 'Incorrect password. Please try again.';
            errEl.style.display = 'block';

            const pwInput = document.getElementById('vault-unlock-password');
            if (pwInput) pwInput.select();
        }
    } catch (_) {
        btn.disabled = false;
        const textEl   = btn.querySelector('.btn-text');
        const loaderEl = btn.querySelector('.btn-loader');
        if (textEl)   textEl.classList.remove('d-none');
        if (loaderEl) loaderEl.classList.add('d-none');
        errEl.textContent   = 'Network error. Please try again.';
        errEl.style.display = 'block';
    }
}

// ── Remove the overlay ────────────────────────────────────────
function _dismissLockOverlay() {
    const overlay = document.getElementById('vault-lock-overlay');
    if (overlay) {
        overlay.style.opacity    = '0';
        overlay.style.transition = 'opacity 0.2s ease';
        setTimeout(() => overlay.remove(), 200);
    }
    _lockOverlayVisible = false;
}

// ── Promise-based unlock gate ─────────────────────────────────
// Resolves true once unlocked, or false if user navigates away.
async function waitForVaultUnlock() {
    let mode = 'password';
    try {
        const res  = await fetch('/api/vault/status');
        const data = await res.json();
        if (!data.has_password) mode = 'set-password';
    } catch (_) {}

    return new Promise((resolve) => {
        _vaultUnlockResolve = resolve;
        _showVaultLockOverlay(mode);
    });
}

// ── Fetch wrapper: intercepts 423 and shows unlock prompt ─────
async function fetchWithVaultGate(url, options = {}) {
    let res = await fetch(url, options);

    if (res.status === 423) {
        const unlocked = await waitForVaultUnlock();
        if (!unlocked) return res;
        res = await fetch(url, options);
    }

    return res;
}

// ── Manual lock ───────────────────────────────────────────────
async function lockVaultManually() {
    try {
        await fetch('/api/vault/lock', { method: 'POST' });
        stopVaultLockPoller();
        let mode = 'password';
        try {
            const res  = await fetch('/api/vault/status');
            const data = await res.json();
            if (!data.has_password) mode = 'set-password';
        } catch (_) {}
        _showVaultLockOverlay(mode);
    } catch (_) {}
}