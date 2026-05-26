// ─────────────────────────────────────────────────────────────
// 2fa.js — VaultKey 2FA verification page
// Handles TOTP verify, backup code verify, and section toggling.
// No master_password is ever stored or sent — the server uses
// the pre-derived vault key stashed during the login attempt.
// ─────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {

    // ── Element refs ─────────────────────────────────────────
    const totpInput     = document.getElementById('totp-code');
    const backupInput   = document.getElementById('backup-code');

    const totpSection   = document.getElementById('totp-section');
    const backupSection = document.getElementById('backup-section');
    const totpFooter    = document.getElementById('totp-footer');

    const btnVerifyTotp   = document.getElementById('btn-verify-totp');
    const btnVerifyBackup = document.getElementById('btn-verify-backup');
    const btnUseBackup    = document.getElementById('btn-use-backup');
    const btnBackToTotp   = document.getElementById('btn-back-to-totp');

    const alertBox   = document.getElementById('auth-alert');
    const successBox = document.getElementById('auth-success');

    // ── Auto-format TOTP input (adds space after 3 digits) ───
    if (totpInput) {
        totpInput.addEventListener('input', function () {
            let raw = this.value.replace(/\D/g, '').slice(0, 6);
            this.value = raw.length > 3
                ? raw.slice(0, 3) + ' ' + raw.slice(3)
                : raw;
        });

        totpInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') verifyTOTP();
        });
    }

    // ── Auto-format backup code (XXXX-XXXX-XXXX-XXXX) ────────
    if (backupInput) {
        backupInput.addEventListener('input', function () {
            let raw = this.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 16);
            if (raw.length > 12) {
                raw = raw.slice(0, 4) + '-' + raw.slice(4, 8) + '-' + raw.slice(8, 12) + '-' + raw.slice(12);
            } else if (raw.length > 8) {
                raw = raw.slice(0, 4) + '-' + raw.slice(4, 8) + '-' + raw.slice(8);
            } else if (raw.length > 4) {
                raw = raw.slice(0, 4) + '-' + raw.slice(4);
            }
            this.value = raw;
        });

        backupInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') verifyBackup();
        });
    }

    // ── Section toggles ───────────────────────────────────────
    if (btnUseBackup) {
        btnUseBackup.addEventListener('click', () => {
            showSection('backup');
            clearAlerts();
        });
    }

    if (btnBackToTotp) {
        btnBackToTotp.addEventListener('click', () => {
            showSection('totp');
            clearAlerts();
        });
    }

    // ── Button listeners ──────────────────────────────────────
    if (btnVerifyTotp)   btnVerifyTotp.addEventListener('click', verifyTOTP);
    if (btnVerifyBackup) btnVerifyBackup.addEventListener('click', verifyBackup);


    // ─────────────────────────────────────────────────────────
    // showSection — switches between totp / backup views
    // ─────────────────────────────────────────────────────────
    function showSection(which) {
        if (which === 'backup') {
            if (totpSection)  { totpSection.style.display  = 'none'; }
            if (totpFooter)   { totpFooter.style.display   = 'none'; }
            if (backupSection) {
                backupSection.style.display = 'block';
                backupSection.classList.add('tfa-section');
            }
            if (backupInput) backupInput.focus();
        } else {
            if (backupSection) { backupSection.style.display = 'none'; }
            if (totpSection) {
                totpSection.style.display = 'block';
                totpSection.classList.add('tfa-section');
            }
            if (totpFooter) { totpFooter.style.display = 'block'; }
            if (totpInput) {
                totpInput.value = '';
                totpInput.focus();
            }
        }
    }


    // ─────────────────────────────────────────────────────────
    // verifyTOTP
    // POSTs the 6-digit code to /api/2fa/verify-login.
    // The server completes the login using the pre-derived vault
    // key stored temporarily in the pending session — never the
    // raw master password.
    // ─────────────────────────────────────────────────────────
    async function verifyTOTP() {
        const code = (totpInput ? totpInput.value.replace(/\s/g, '').trim() : '');

        if (!code || code.length !== 6) {
            showAlert('Please enter the 6-digit code from your authenticator app.');
            return;
        }

        setLoading(btnVerifyTotp, true);
        clearAlerts();

        try {
            const res  = await fetch('/api/2fa/verify-login', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ code })
            });
            const data = await res.json();

            if (res.ok) {
                showSuccess('Verified! Redirecting to your vault\u2026');
                setTimeout(() => { window.location.href = '/dashboard'; }, 800);
            } else {
                setLoading(btnVerifyTotp, false);
                showAlert(data.error || 'Invalid code. Please try again.');
                if (totpInput) {
                    totpInput.value = '';
                    totpInput.focus();
                }
            }
        } catch (err) {
            setLoading(btnVerifyTotp, false);
            showAlert('Something went wrong. Please try again.');
        }
    }


    // ─────────────────────────────────────────────────────────
    // verifyBackup
    // POSTs the backup code to /api/2fa/verify-backup.
    // Same vault-key approach — no raw password involved.
    // ─────────────────────────────────────────────────────────
    async function verifyBackup() {
        const code = (backupInput ? backupInput.value.trim() : '');

        if (!code) {
            showAlert('Please enter a backup code.');
            return;
        }

        setLoading(btnVerifyBackup, true);
        clearAlerts();

        try {
            const res  = await fetch('/api/2fa/verify-backup', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ code })
            });
            const data = await res.json();

            if (res.ok) {
                const remaining = data.backup_codes_remaining;
                const isLow     = remaining <= 2;
                const msg = isLow
                    ? `Signed in! You have ${remaining} backup code${remaining === 1 ? '' : 's'} left \u2014 consider regenerating them in Profile \u2192 Security.`
                    : 'Verified! Redirecting to your vault\u2026';
                showSuccess(msg);
                setTimeout(() => { window.location.href = '/dashboard'; }, isLow ? 2400 : 900);
            } else {
                setLoading(btnVerifyBackup, false);
                showAlert(data.error || 'Invalid backup code. Please try again.');
            }
        } catch (err) {
            setLoading(btnVerifyBackup, false);
            showAlert('Something went wrong. Please try again.');
        }
    }


    // ─────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────

    function showAlert(msg) {
        if (!alertBox || !successBox) return;
        alertBox.textContent = msg;
        alertBox.classList.remove('d-none');
        successBox.classList.add('d-none');
    }

    function showSuccess(msg) {
        if (!alertBox || !successBox) return;
        successBox.textContent = msg;
        successBox.classList.remove('d-none');
        alertBox.classList.add('d-none');
    }

    function clearAlerts() {
        if (alertBox)   alertBox.classList.add('d-none');
        if (successBox) successBox.classList.add('d-none');
    }

    function setLoading(btn, loading) {
        if (!btn) return;
        const textEl   = btn.querySelector('.btn-text');
        const loaderEl = btn.querySelector('.btn-loader');
        btn.disabled = loading;
        if (textEl)   textEl.classList.toggle('d-none', loading);
        if (loaderEl) loaderEl.classList.toggle('d-none', !loading);
    }

});