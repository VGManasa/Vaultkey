// profile.js — VaultKey
// Vault key architecture: master password is NEVER stored in
// session. Only the derived vault key bytes live in the session.

document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    setupPasswordStrength();
    setupSlider();
    setupAvatarColor();
    setupButtons();
    loadPrefs();
    load2FAStatus();
    detectGoogleUserPasswordState();
});


// ── Active user scoping ──────────────────────────────────────
let _activeUserId    = null;
let _userHasPassword = true;

async function getActiveUserId() {
    if (_activeUserId !== null) return _activeUserId;
    try {
        const res  = await fetch('/api/accounts');
        const data = await res.json();
        _activeUserId = data.active_user;
    } catch (_) {
        _activeUserId = 'default';
    }
    return _activeUserId;
}

async function prefsKey() {
    const uid = await getActiveUserId();
    return `vk_prefs_${uid}`;
}


// ── Detect Google users who haven't set a master password ────
async function detectGoogleUserPasswordState() {
    try {
        const res  = await fetch('/api/vault/status');
        const data = await res.json();
        _userHasPassword = data.has_password;

        if (!_userHasPassword) {
            _adaptPasswordCardForGoogleUser();
        }
    } catch (_) {}
}

function _adaptPasswordCardForGoogleUser() {
    const currentPwGroup = document.getElementById('current-password')?.closest('.field-group');
    if (currentPwGroup) currentPwGroup.style.display = 'none';

    const sub = document.querySelector('#change-password-card .profile-card-sub');
    if (sub) sub.textContent = 'Set a master password to encrypt your vault';

    const title = document.querySelector('#change-password-card .profile-card-title');
    if (title) title.textContent = 'Set Master Password';

    const btn = document.getElementById('btn-save-password');
    if (btn) btn.textContent = 'Set Master Password';

    const infoEl = document.getElementById('google-pw-notice');
    if (infoEl) infoEl.style.display = 'flex';
}


// ── Sidebar ───────────────────────────────────────────────────
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
}

// ── Logout ────────────────────────────────────────────────────
async function logout() {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login';
}

// ── Password Toggle ───────────────────────────────────────────
function togglePassword(id) {
    const input = document.getElementById(id);
    input.type = input.type === 'password' ? 'text' : 'password';
}

// ── Toast ─────────────────────────────────────────────────────
function showToast(message, type = '') {
    const container = document.getElementById('toast-container');
    const toast     = document.createElement('div');
    toast.className   = `toast-msg${type ? ' ' + type : ''}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity    = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(() => { if (toast.parentNode) container.removeChild(toast); }, 300);
    }, 2500);
}

// ── Inline Alerts ─────────────────────────────────────────────
function showError(message) {
    const alertBox   = document.getElementById('profile-alert');
    const successBox = document.getElementById('profile-success');
    successBox.classList.add('d-none');
    alertBox.textContent = message;
    alertBox.classList.remove('d-none');
    setTimeout(() => alertBox.classList.add('d-none'), 3500);
}

function showSuccess(message) {
    const alertBox   = document.getElementById('profile-alert');
    const successBox = document.getElementById('profile-success');
    alertBox.classList.add('d-none');
    successBox.textContent = message;
    successBox.classList.remove('d-none');
    setTimeout(() => successBox.classList.add('d-none'), 3500);
}

// ── Load Stats ────────────────────────────────────────────────
async function loadStats() {
    try {
        const res  = await fetch('/api/stats');
        const data = await res.json();
        document.getElementById('hero-notebooks').textContent = data.notebooks;
        document.getElementById('hero-entries').textContent   = data.entries;
        document.getElementById('hero-since').textContent     = data.member_since;
        document.getElementById('act-notebooks').textContent  = data.notebooks;
        document.getElementById('act-entries').textContent    = data.entries;
        document.getElementById('act-since').textContent      = data.member_since;
    } catch (err) {
        console.error(err);
    }
}

// ── Load Preferences ─────────────────────────────────────────
async function loadPrefs() {
    try {
        const key   = await prefsKey();
        const saved = localStorage.getItem(key);
        if (!saved) return;
        const prefs = JSON.parse(saved);
        if (typeof prefs.autolock      !== 'undefined') document.getElementById('pref-autolock').checked       = prefs.autolock;
        if (typeof prefs.strength      !== 'undefined') document.getElementById('pref-strength').checked       = prefs.strength;
        if (typeof prefs.confirmDelete !== 'undefined') document.getElementById('pref-confirm-delete').checked = prefs.confirmDelete;
        if (typeof prefs.pwLength      !== 'undefined') {
            const slider = document.getElementById('pref-pw-length');
            slider.value = prefs.pwLength;
            document.getElementById('pref-pw-length-val').textContent = prefs.pwLength;
        }
    } catch (err) {
        console.error('loadPrefs error:', err);
    }
}

// ── Password Strength — 4-block scale ─────────────────────────
function setupPasswordStrength() {
    const input  = document.getElementById('new-password');
    const colors = ['', '#ff5f6d', '#f0a060', '#4f8ef7', '#c8f060'];
    const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];

    input.addEventListener('input', () => {
        const value = input.value;
        let score = 0;
        if (value.length >= 8)           score++;
        if (/[A-Z]/.test(value))         score++;
        if (/[0-9]/.test(value))         score++;
        if (/[^A-Za-z0-9]/.test(value))  score++;

        for (let i = 1; i <= 4; i++) {
            document.getElementById(`sb-${i}`).style.background = i <= score ? colors[score] : 'var(--border2)';
        }
        const labelEl = document.getElementById('pw-strength-label');
        labelEl.textContent = value.length ? (labels[score] || '') : '';
        labelEl.style.color = colors[score] || 'var(--text3)';
    });
}

// ── Slider ────────────────────────────────────────────────────
function setupSlider() {
    const slider = document.getElementById('pref-pw-length');
    const val    = document.getElementById('pref-pw-length-val');
    slider.addEventListener('input', () => { val.textContent = slider.value; });
}

// ── Avatar Color ──────────────────────────────────────────────
function setupAvatarColor() {
    const btn = document.getElementById('avatar-change-btn');
    btn.addEventListener('click', () => {
        new bootstrap.Modal(document.getElementById('avatarColorModal')).show();
    });

    let selectedColor = '#c8f060';
    document.querySelectorAll('#avatar-color-picker .color-swatch').forEach(swatch => {
        swatch.addEventListener('click', () => {
            document.querySelectorAll('#avatar-color-picker .color-swatch').forEach(s => s.classList.remove('active'));
            swatch.classList.add('active');
            selectedColor = swatch.dataset.color;
        });
    });

    document.getElementById('btn-save-avatar-color').addEventListener('click', () => {
        document.getElementById('profile-avatar').style.background = selectedColor;
        document.querySelector('.user-avatar').style.background    = selectedColor;
        bootstrap.Modal.getInstance(document.getElementById('avatarColorModal')).hide();
        showToast('Avatar color updated', 'success');
    });
}


// ── Generic Confirm Modal ─────────────────────────────────────
function openConfirmModal({ icon, title, lines, confirmLabel, confirmClass }) {
    return new Promise((resolve) => {
        const iconWrap = document.getElementById('confirm-modal-icon');
        iconWrap.innerHTML = icon;
        iconWrap.className = `confirm-modal-icon-wrap ${confirmClass === 'btn-danger' ? 'danger' : ''}`;

        document.getElementById('confirm-modal-title').textContent = title;

        const body = document.getElementById('confirm-modal-lines');
        body.innerHTML = lines.map(l => `<p class="confirm-modal-line">${l}</p>`).join('');

        const confirmBtn = document.getElementById('confirm-modal-ok');
        confirmBtn.textContent = confirmLabel;
        confirmBtn.className   = confirmClass || 'btn-confirm';

        const modalEl = document.getElementById('confirmModal');
        const modal   = new bootstrap.Modal(modalEl);
        modal.show();

        function onConfirm() { cleanup(); modal.hide(); resolve(true); }
        function onCancel()  { cleanup(); resolve(false); }
        function cleanup() {
            confirmBtn.removeEventListener('click', onConfirm);
            document.getElementById('confirm-modal-cancel').removeEventListener('click', onCancel);
            modalEl.removeEventListener('hide.bs.modal', onCancel);
        }

        confirmBtn.addEventListener('click', onConfirm);
        document.getElementById('confirm-modal-cancel').addEventListener('click', onCancel);
        modalEl.addEventListener('hide.bs.modal', onCancel, { once: true });
    });
}


// ── Button wiring ─────────────────────────────────────────────
function setupButtons() {
    document.getElementById('btn-save-account').addEventListener('click',  handleSaveAccount);
    document.getElementById('btn-save-password').addEventListener('click', handleSavePassword);
    document.getElementById('btn-save-prefs').addEventListener('click',    handleSavePrefs);
    document.getElementById('btn-export').addEventListener('click',        handleExport);
    document.getElementById('btn-delete-all-nb').addEventListener('click', handleClearVault);
    document.getElementById('btn-delete-account').addEventListener('click', () => {
        new bootstrap.Modal(document.getElementById('deleteAccountModal')).show();
    });
    document.getElementById('btn-confirm-delete-account').addEventListener('click', deleteAccount);

    document.getElementById('btn-enable-2fa').addEventListener('click',         start2FASetup);
    document.getElementById('btn-disable-2fa').addEventListener('click',        open2FADisableModal);
    document.getElementById('btn-regen-backup').addEventListener('click',       openRegenBackupModal);
    document.getElementById('btn-2fa-verify').addEventListener('click',         confirm2FASetup);
    document.getElementById('totp-setup-code').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') confirm2FASetup();
    });
    document.getElementById('btn-disable-2fa-confirm').addEventListener('click', disable2FA);
    document.getElementById('btn-regen-backup-confirm').addEventListener('click', regenBackupCodes);
    document.getElementById('btn-copy-backup').addEventListener('click',          copyBackupCodes);
}


// ── Save Account ──────────────────────────────────────────────
async function handleSaveAccount() {
    const username = document.getElementById('upd-username').value.trim();
    if (!username) { showError('Username is required'); return; }

    const confirmed = await openConfirmModal({
        icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                   <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                   <circle cx="12" cy="7" r="4"/>
               </svg>`,
        title: 'Update Username',
        lines: [
            `You're about to change your username to <strong>${username}</strong>.`,
            'This will update your display name across your vault.'
        ],
        confirmLabel: 'Yes, Update',
        confirmClass: 'btn-confirm'
    });
    if (!confirmed) return;

    try {
        const res  = await fetch('/api/profile/update-account', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const data = await res.json();
        if (!res.ok) { showError(data.error); return; }

        document.querySelector('.profile-name').textContent   = username;
        document.querySelector('.user-name').textContent      = username;
        document.getElementById('profile-avatar').textContent = username.charAt(0).toUpperCase();

        showToast('Username updated successfully', 'success');
    } catch (err) {
        console.error(err);
        showError('Failed to update account');
    }
}


// ── Save Password ─────────────────────────────────────────────
// Handles two cases:
//   1. Existing password user — current_password required.
//   2. Google user setting password for the first time — only new_password.
async function handleSavePassword() {
    const current_password = document.getElementById('current-password').value;
    const new_password     = document.getElementById('new-password').value;
    const confirm_password = document.getElementById('confirm-password').value;

    if (_userHasPassword && !current_password) { showError('Please enter your current password'); return; }
    if (!new_password)                         { showError('Please enter a new password'); return; }
    if (new_password !== confirm_password)     { showError('Passwords do not match'); return; }
    if (new_password.length < 8)               { showError('Password must be at least 8 characters'); return; }

    const isSettingFirst = !_userHasPassword;

    const confirmed = await openConfirmModal({
        icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                   <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                   <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
               </svg>`,
        title: isSettingFirst ? 'Set Master Password' : 'Change Master Password',
        lines: isSettingFirst
            ? [
                'You\'re about to set your <strong>master password</strong> for the first time.',
                'This password will encrypt all entries in your vault. It <strong>cannot be recovered</strong> if lost — store it safely.'
              ]
            : [
                'You\'re about to update your <strong>master password</strong>.',
                'All your stored passwords will remain accessible with the new master password. Make sure you remember it — it cannot be recovered.'
              ],
        confirmLabel: isSettingFirst ? 'Yes, Set Password' : 'Yes, Change Password',
        confirmClass: 'btn-confirm'
    });
    if (!confirmed) return;

    try {
        const body = { new_password };
        if (_userHasPassword) body.current_password = current_password;

        const res  = await fetch('/api/profile/change-password', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!res.ok) { showError(data.error); return; }

        // Clear all password fields
        document.getElementById('current-password').value = '';
        document.getElementById('new-password').value     = '';
        document.getElementById('confirm-password').value = '';
        for (let i = 1; i <= 4; i++) {
            document.getElementById(`sb-${i}`).style.background = 'var(--border2)';
        }
        document.getElementById('pw-strength-label').textContent = '';

        _userHasPassword = true;

        // Restore card to normal state
        const currentPwGroup = document.getElementById('current-password')?.closest('.field-group');
        if (currentPwGroup) currentPwGroup.style.display = '';
        const sub = document.querySelector('#change-password-card .profile-card-sub');
        if (sub) sub.textContent = 'Update your master password';
        const title = document.querySelector('#change-password-card .profile-card-title');
        if (title) title.textContent = 'Change Password';
        const btn = document.getElementById('btn-save-password');
        if (btn) btn.textContent = 'Update Password';
        const infoEl = document.getElementById('google-pw-notice');
        if (infoEl) infoEl.style.display = 'none';

        const msg = isSettingFirst
            ? 'Master password set — vault is now encrypted'
            : 'Master password updated successfully';
        showToast(msg, 'success');

        // If setting for the first time, unlock the vault in the session
        if (isSettingFirst) {
            try {
                await fetch('/api/vault/unlock', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    JSON.stringify({ password: new_password })
                });
            } catch (_) {}
        }
    } catch (err) {
        console.error(err);
        showError('Failed to update password');
    }
}


// ── Save Preferences ──────────────────────────────────────────
async function handleSavePrefs() {
    const autolock      = document.getElementById('pref-autolock').checked;
    const strength      = document.getElementById('pref-strength').checked;
    const confirmDelete = document.getElementById('pref-confirm-delete').checked;
    const pwLength      = document.getElementById('pref-pw-length').value;

    const summary = [
        `Auto-lock: <strong>${autolock ? 'On' : 'Off'}</strong>`,
        `Show password strength: <strong>${strength ? 'On' : 'Off'}</strong>`,
        `Confirm before delete: <strong>${confirmDelete ? 'On' : 'Off'}</strong>`,
        `Generated password length: <strong>${pwLength} characters</strong>`
    ].join(' &nbsp;·&nbsp; ');

    const confirmed = await openConfirmModal({
        icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                   <circle cx="12" cy="12" r="3"/>
                   <path d="M19.07 4.93l-1.41 1.41M4.93 4.93l1.41 1.41M19.07 19.07l-1.41-1.41M4.93 19.07l1.41-1.41M12 2v2M12 20v2M2 12h2M20 12h2"/>
               </svg>`,
        title: 'Save Preferences',
        lines: ['Confirm the following preferences:', summary],
        confirmLabel: 'Save Preferences',
        confirmClass: 'btn-confirm'
    });
    if (!confirmed) return;

    try {
        const key = await prefsKey();
        localStorage.setItem(key, JSON.stringify({ autolock, strength, confirmDelete, pwLength }));
    } catch (_) {}

    showToast('Preferences saved', 'success');
}


// ── Export Vault ──────────────────────────────────────────────
async function handleExport() {
    const confirmed = await openConfirmModal({
        icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                   <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                   <polyline points="7 10 12 15 17 10"/>
                   <line x1="12" y1="15" x2="12" y2="3"/>
               </svg>`,
        title: 'Export Vault Data',
        lines: [
            'Your vault will be exported as a <strong>JSON file</strong>.',
            'Note: passwords are exported as plain text. Store the file somewhere safe and do not share it.'
        ],
        confirmLabel: 'Export Now',
        confirmClass: 'btn-confirm'
    });
    if (!confirmed) return;

    try {
        const res  = await fetch('/api/profile/export');
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = 'vaultkey-export.json';
        a.click();
        URL.revokeObjectURL(url);
        showToast('Vault exported successfully', 'success');
    } catch (err) {
        console.error(err);
        showError('Failed to export vault');
    }
}


// ── Clear Vault ───────────────────────────────────────────────
async function handleClearVault() {
    const confirmed = await openConfirmModal({
        icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                   <polyline points="3 6 5 6 21 6"/>
                   <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                   <path d="M10 11v6"/><path d="M14 11v6"/>
               </svg>`,
        title: 'Delete All Notebooks',
        lines: [
            'This will <strong>permanently delete</strong> all your notebooks and every password entry inside them.',
            'This action cannot be undone. Are you sure you want to clear your entire vault?'
        ],
        confirmLabel: 'Yes, Clear Vault',
        confirmClass: 'btn-danger'
    });
    if (!confirmed) return;

    try {
        const res  = await fetch('/api/profile/delete-all-notebooks', { method: 'DELETE' });
        const data = await res.json();
        if (!res.ok) { showError(data.error); return; }
        showToast('Vault cleared', 'success');
        setTimeout(() => { window.location.href = '/dashboard'; }, 1200);
    } catch (err) {
        console.error(err);
        showError('Failed to clear vault');
    }
}


// ── Delete Account ────────────────────────────────────────────
async function deleteAccount() {
    const password = document.getElementById('delete-confirm-password').value;
    const errBox   = document.getElementById('delete-account-error');

    if (!password) {
        errBox.textContent = 'Please enter your password';
        errBox.classList.remove('d-none');
        return;
    }

    try {
        const res  = await fetch('/api/profile/delete-account', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        const data = await res.json();
        if (!res.ok) {
            errBox.textContent = data.error;
            errBox.classList.remove('d-none');
            return;
        }
        try {
            const key = await prefsKey();
            localStorage.removeItem(key);
        } catch (_) {}
        window.location.href = '/register';
    } catch (err) {
        console.error(err);
        showError('Failed to delete account');
    }
}


// ═════════════════════════════════════════════════════════════
// 2FA — Load Status
// ═════════════════════════════════════════════════════════════

async function load2FAStatus() {
    try {
        const res = await fetch('/api/2fa/status');
        if (!res.ok) { render2FAStatus(false, 0, true); return; }
        const data = await res.json();
        render2FAStatus(data.totp_enabled, data.backup_codes_count, false);
    } catch (err) {
        console.error('load2FAStatus error:', err);
        render2FAStatus(false, 0, true);
    }
}

function render2FAStatus(enabled, backupCount, fetchFailed = false) {
    const dot        = document.getElementById('2fa-status-dot');
    const badge      = document.getElementById('2fa-status-badge');
    const sub        = document.getElementById('2fa-security-sub');
    const enableBtn  = document.getElementById('btn-enable-2fa');
    const disableBtn = document.getElementById('btn-disable-2fa');
    const regenRow   = document.getElementById('2fa-regen-row');
    const backupSub  = document.getElementById('2fa-backup-sub');

    if (fetchFailed) {
        dot.className     = 'security-dot yellow';
        badge.textContent = '—';
        badge.className   = 'security-badge warn';
        sub.textContent   = 'Could not load status';
        enableBtn.classList.add('d-none');
        disableBtn.classList.add('d-none');
        regenRow.classList.add('d-none');
        return;
    }

    if (enabled) {
        dot.className     = 'security-dot green';
        badge.textContent = 'Enabled';
        badge.className   = 'security-badge good';
        sub.textContent   = 'Authenticator app active';
        enableBtn.classList.add('d-none');
        disableBtn.classList.remove('d-none');
        regenRow.classList.remove('d-none');

        if (backupSub) {
            backupSub.textContent = backupCount === 1
                ? '1 backup code remaining'
                : `${backupCount} backup codes remaining`;
            backupSub.style.color = backupCount <= 2 ? '#f0a060' : '';
        }
    } else {
        dot.className     = 'security-dot yellow';
        badge.textContent = 'Off';
        badge.className   = 'security-badge warn';
        sub.textContent   = 'Not configured — your account is less secure';
        enableBtn.classList.remove('d-none');
        disableBtn.classList.add('d-none');
        regenRow.classList.add('d-none');
    }
}


// ═════════════════════════════════════════════════════════════
// 2FA — Setup Flow
// ═════════════════════════════════════════════════════════════

async function start2FASetup() {
    // Google users must set a master password before enabling 2FA
    if (!_userHasPassword) {
        showError('Please set a master password before enabling two-factor authentication.');
        document.getElementById('change-password-card')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        return;
    }

    const btn = document.getElementById('btn-enable-2fa');
    btn.disabled    = true;
    btn.textContent = 'Loading…';

    try {
        const res  = await fetch('/api/2fa/setup', { method: 'POST' });
        const data = await res.json();

        if (!res.ok) {
            showToast(data.error || 'Failed to start 2FA setup', 'error');
            btn.disabled    = false;
            btn.textContent = 'Enable';
            return;
        }

        document.getElementById('totp-qr-container').innerHTML  = data.qr_svg;
        document.getElementById('totp-secret-display').textContent = data.secret;
        document.getElementById('totp-setup-code').value        = '';
        document.getElementById('totp-setup-error').classList.add('d-none');
        document.getElementById('totp-setup-error').textContent = '';

        btn.disabled    = false;
        btn.textContent = 'Enable';

        new bootstrap.Modal(document.getElementById('setup2FAModal')).show();
    } catch (err) {
        console.error(err);
        showToast('Failed to start 2FA setup', 'error');
        btn.disabled    = false;
        btn.textContent = 'Enable';
    }
}

async function confirm2FASetup() {
    const code    = document.getElementById('totp-setup-code').value.trim().replace(/\s/g, '');
    const errorEl = document.getElementById('totp-setup-error');
    const btn     = document.getElementById('btn-2fa-verify');

    if (!code || code.length !== 6) {
        errorEl.textContent = 'Please enter the 6-digit code from your app.';
        errorEl.classList.remove('d-none');
        return;
    }

    btn.disabled = true;
    const textEl   = btn.querySelector('.btn-text');
    const loaderEl = btn.querySelector('.btn-loader');
    if (textEl)   textEl.classList.add('d-none');
    if (loaderEl) loaderEl.style.display = 'inline-block';
    errorEl.classList.add('d-none');

    try {
        const res  = await fetch('/api/2fa/confirm', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ code })
        });
        const data = await res.json();

        btn.disabled = false;
        if (textEl)   textEl.classList.remove('d-none');
        if (loaderEl) loaderEl.style.display = 'none';

        if (!res.ok) {
            errorEl.textContent = data.error || 'Invalid code. Please try again.';
            errorEl.classList.remove('d-none');
            return;
        }

        bootstrap.Modal.getInstance(document.getElementById('setup2FAModal')).hide();
        showBackupCodesModal(data.backup_codes, true);
        await load2FAStatus();
        showToast('Two-factor authentication enabled', 'success');
    } catch (err) {
        console.error(err);
        btn.disabled = false;
        if (textEl)   textEl.classList.remove('d-none');
        if (loaderEl) loaderEl.style.display = 'none';
        errorEl.textContent = 'Something went wrong. Please try again.';
        errorEl.classList.remove('d-none');
    }
}


// ── Backup Codes Modal ────────────────────────────────────────
function showBackupCodesModal(codes, isNew = false) {
    const titleEl = document.getElementById('backup-codes-modal-title');
    const noteEl  = document.getElementById('backup-codes-note');
    const listEl  = document.getElementById('backup-codes-list');

    titleEl.textContent = isNew ? 'Save Your Backup Codes' : 'New Backup Codes';
    noteEl.innerHTML    = isNew
        ? 'Your 2FA is now enabled. <strong>Save these backup codes</strong> somewhere safe — they\'re shown <strong>only once</strong> and can be used if you lose access to your authenticator app.'
        : '<strong>Your old backup codes have been replaced.</strong> Save these new codes somewhere safe.';

    listEl.innerHTML = codes.map(code =>
        `<div class="backup-code-item"><span class="backup-code-text">${code}</span></div>`
    ).join('');

    listEl.dataset.codes = codes.join('\n');
    new bootstrap.Modal(document.getElementById('backupCodesModal')).show();
}

function copyBackupCodes() {
    const listEl = document.getElementById('backup-codes-list');
    const codes  = listEl.dataset.codes || '';
    navigator.clipboard.writeText(codes).then(() => {
        const btn = document.getElementById('btn-copy-backup');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy All Codes'; }, 2000);
    }).catch(() => { showToast('Failed to copy codes', 'error'); });
}


// ── Disable 2FA ───────────────────────────────────────────────
function open2FADisableModal() {
    document.getElementById('disable-2fa-password').value = '';
    document.getElementById('disable-2fa-error').classList.add('d-none');
    new bootstrap.Modal(document.getElementById('disable2FAModal')).show();
}

async function disable2FA() {
    const password = document.getElementById('disable-2fa-password').value;
    const errorEl  = document.getElementById('disable-2fa-error');
    const btn      = document.getElementById('btn-disable-2fa-confirm');

    if (!password) {
        errorEl.textContent = 'Please enter your master password.';
        errorEl.classList.remove('d-none');
        return;
    }

    btn.disabled    = true;
    btn.textContent = 'Disabling…';
    errorEl.classList.add('d-none');

    try {
        const res  = await fetch('/api/2fa/disable', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ password })
        });
        const data = await res.json();

        btn.disabled    = false;
        btn.textContent = 'Yes, Disable 2FA';

        if (!res.ok) {
            errorEl.textContent = data.error || 'Incorrect password.';
            errorEl.classList.remove('d-none');
            return;
        }

        bootstrap.Modal.getInstance(document.getElementById('disable2FAModal')).hide();
        showToast('Two-factor authentication disabled', 'success');
        await load2FAStatus();
    } catch (err) {
        console.error(err);
        btn.disabled    = false;
        btn.textContent = 'Yes, Disable 2FA';
        errorEl.textContent = 'Something went wrong. Please try again.';
        errorEl.classList.remove('d-none');
    }
}


// ── Regenerate Backup Codes ───────────────────────────────────
function openRegenBackupModal() {
    document.getElementById('regen-backup-password').value = '';
    document.getElementById('regen-backup-error').classList.add('d-none');
    new bootstrap.Modal(document.getElementById('regenBackupModal')).show();
}

async function regenBackupCodes() {
    const password = document.getElementById('regen-backup-password').value;
    const errorEl  = document.getElementById('regen-backup-error');
    const btn      = document.getElementById('btn-regen-backup-confirm');

    if (!password) {
        errorEl.textContent = 'Please enter your master password.';
        errorEl.classList.remove('d-none');
        return;
    }

    btn.disabled    = true;
    btn.textContent = 'Regenerating…';
    errorEl.classList.add('d-none');

    try {
        const res  = await fetch('/api/2fa/regenerate-backup', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ password })
        });
        const data = await res.json();

        btn.disabled    = false;
        btn.textContent = 'Yes, Regenerate';

        if (!res.ok) {
            errorEl.textContent = data.error || 'Incorrect password.';
            errorEl.classList.remove('d-none');
            return;
        }

        bootstrap.Modal.getInstance(document.getElementById('regenBackupModal')).hide();
        showBackupCodesModal(data.backup_codes, false);
        await load2FAStatus();
    } catch (err) {
        console.error(err);
        btn.disabled    = false;
        btn.textContent = 'Yes, Regenerate';
        errorEl.textContent = 'Something went wrong. Please try again.';
        errorEl.classList.remove('d-none');
    }
}