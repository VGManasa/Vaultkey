// dashboard.js — VaultKey

let notebooks = [];
let currentNotebookId = null;
let editingEntryId = null;
let allEntries = [];

// ── Close dropdowns when clicking outside ────────────────────
document.addEventListener('click', (e) => {
    if (!e.target.closest('.nb-menu-wrap')) {
        document.querySelectorAll('.nb-dropdown').forEach(d => d.classList.remove('open'));
    }
    if (!e.target.closest('.acct-switcher-wrap')) {
        closeAccountSwitcher();
    }
});

// ── Init ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

    loadStats();
    loadNotebooks();
    loadAccounts();
    startVaultLockPoller();

    const acctWrap = document.querySelector('.acct-switcher-wrap');
    if (acctWrap) acctWrap.addEventListener('click', toggleAccountSwitcher);

    document.getElementById('color-picker').addEventListener('click', (e) => {
        const swatch = e.target.closest('.color-swatch');
        if (!swatch) return;
        document.querySelectorAll('#color-picker .color-swatch').forEach(s => s.classList.remove('active'));
        swatch.classList.add('active');
    });

    document.getElementById('btn-new-notebook').addEventListener('click', () => {
        document.getElementById('nb-name').value = '';
        document.getElementById('nb-desc').value = '';
        document.querySelectorAll('#color-picker .color-swatch').forEach(s => s.classList.remove('active'));
        const first = document.querySelector('#color-picker .color-swatch');
        if (first) first.classList.add('active');
        new bootstrap.Modal(document.getElementById('notebookModal')).show();
    });

    document.getElementById('btn-save-notebook').addEventListener('click', createNotebook);

    document.getElementById('btn-add-entry').addEventListener('click', () => {
        editingEntryId = null;
        resetEntryForm();
        const oldGroup = document.getElementById('old-password-group');
        if (oldGroup) oldGroup.style.display = 'none';
        document.getElementById('entryModalTitle').textContent = 'New Entry';
        new bootstrap.Modal(document.getElementById('entryModal')).show();
    });

    document.getElementById('btn-save-entry').addEventListener('click', createOrUpdateEntry);

    document.getElementById('global-search').addEventListener('input', debounce(handleSearch, 250));
    document.getElementById('entry-search').addEventListener('input', debounce(filterEntries, 200));

    document.getElementById('btn-confirm-logout').addEventListener('click', logoutCurrent);
    document.getElementById('btn-confirm-logout-all').addEventListener('click', logoutAll);

    setupEntryStrengthMeter();
    injectVKModals();

    // 2FA nudge banner
    (async function check2FANudge() {
        try {
            const res  = await fetch('/api/2fa/status');
            const data = await res.json();
            if (!data.totp_enabled) {
                const nudge = document.getElementById('dashboard-2fa-nudge');
                if (nudge) nudge.style.display = 'block';
            }
        } catch (_) {}
    })();
});


// ═════════════════════════════════════════════════════════════
// VK Modal System
// ═════════════════════════════════════════════════════════════

function injectVKModals() {
    if (!document.getElementById('vkConfirmModal')) {
        const confirmHTML = `
        <div class="modal fade" id="vkConfirmModal" tabindex="-1" aria-hidden="true">
          <div class="modal-dialog modal-dialog-centered modal-sm">
            <div class="modal-content vk-modal" style="border-radius:var(--radius);overflow:hidden;">
              <div class="confirm-modal-head" style="display:flex;align-items:center;gap:0.85rem;padding:1.25rem 1.5rem;">
                <div class="confirm-modal-icon-wrap" id="vk-confirm-icon"></div>
                <h5 class="vk-modal-title" id="vk-confirm-title" style="flex:1;margin:0;">Confirm</h5>
                <button type="button" class="vk-modal-close" data-bs-dismiss="modal">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                  </svg>
                </button>
              </div>
              <div style="height:1px;background:var(--border);margin:0 1.5rem;"></div>
              <div id="vk-confirm-body" style="padding:1.25rem 1.5rem;display:flex;flex-direction:column;gap:0.6rem;"></div>
              <div style="padding:1rem 1.5rem;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:flex-end;gap:0.75rem;">
                <button class="btn-cancel" data-bs-dismiss="modal" id="vk-confirm-cancel">Cancel</button>
                <button class="btn-confirm" id="vk-confirm-ok">Confirm</button>
              </div>
            </div>
          </div>
        </div>`;
        document.body.insertAdjacentHTML('beforeend', confirmHTML);
    }

    if (!document.getElementById('vkRenameModal')) {
        const renameHTML = `
        <div class="modal fade" id="vkRenameModal" tabindex="-1" aria-hidden="true">
          <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content vk-modal">
              <div class="vk-modal-header">
                <h5 class="vk-modal-title">Rename Notebook</h5>
                <button type="button" class="vk-modal-close" data-bs-dismiss="modal">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                  </svg>
                </button>
              </div>
              <div class="vk-modal-body">
                <div class="field-group">
                  <label class="field-label">Current Name</label>
                  <input type="text" id="vk-rename-old" class="field-input" disabled style="opacity:0.5;cursor:not-allowed;"/>
                </div>
                <div class="field-group">
                  <label class="field-label">New Name <span class="required">*</span></label>
                  <input type="text" id="vk-rename-new" class="field-input" placeholder="Enter new notebook name"/>
                  <span class="field-error d-none" id="vk-rename-error"></span>
                </div>
              </div>
              <div class="vk-modal-footer">
                <button class="btn-cancel" data-bs-dismiss="modal">Cancel</button>
                <button class="btn-confirm" id="vk-rename-next">Continue</button>
              </div>
            </div>
          </div>
        </div>`;
        document.body.insertAdjacentHTML('beforeend', renameHTML);
    }
}

// ── Promise-based confirm dialog ─────────────────────────────
function openVKConfirm(opts) {
    return new Promise((resolve) => {
        const modalEl  = document.getElementById('vkConfirmModal');
        const iconWrap = document.getElementById('vk-confirm-icon');
        const titleEl  = document.getElementById('vk-confirm-title');
        const bodyEl   = document.getElementById('vk-confirm-body');
        const okBtn    = document.getElementById('vk-confirm-ok');

        const defaultIcon = opts.isDanger
            ? `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                 <polyline points="3 6 5 6 21 6"/>
                 <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                 <path d="M10 11v6"/><path d="M14 11v6"/>
               </svg>`
            : `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                 <circle cx="12" cy="12" r="10"/>
                 <line x1="12" y1="8" x2="12" y2="12"/>
                 <line x1="12" y1="16" x2="12.01" y2="16"/>
               </svg>`;

        iconWrap.innerHTML = opts.icon || defaultIcon;
        iconWrap.className = `confirm-modal-icon-wrap${opts.isDanger ? ' danger' : ''}`;
        titleEl.textContent = opts.title;

        bodyEl.innerHTML = (opts.lines || [])
            .map(l => `<p class="confirm-modal-line" style="font-size:0.875rem;color:var(--text2);line-height:1.6;margin:0;">${l}</p>`)
            .join('');

        okBtn.textContent = opts.confirmLabel || 'Confirm';
        okBtn.className   = opts.isDanger ? 'btn-danger' : 'btn-confirm';

        const bsModal = new bootstrap.Modal(modalEl);
        bsModal.show();

        function onOk() { cleanup(); bsModal.hide(); resolve(true); }
        function onCancel() { cleanup(); resolve(false); }
        function cleanup() {
            okBtn.removeEventListener('click', onOk);
            modalEl.removeEventListener('hide.bs.modal', onCancel);
        }

        okBtn.addEventListener('click', onOk);
        modalEl.addEventListener('hide.bs.modal', onCancel, { once: true });
    });
}

// ── Rename modal ──────────────────────────────────────────────
function openRenameModal(nb) {
    return new Promise((resolve) => {
        const modalEl  = document.getElementById('vkRenameModal');
        const oldInput = document.getElementById('vk-rename-old');
        const newInput = document.getElementById('vk-rename-new');
        const errorEl  = document.getElementById('vk-rename-error');
        const nextBtn  = document.getElementById('vk-rename-next');

        oldInput.value = nb.name;
        newInput.value = '';
        errorEl.classList.add('d-none');
        errorEl.textContent = '';

        const bsModal = new bootstrap.Modal(modalEl);
        bsModal.show();

        newInput.addEventListener('input', () => errorEl.classList.add('d-none'), { once: false });

        async function onNext() {
            const newName = newInput.value.trim();

            if (!newName) {
                errorEl.textContent = 'Please enter a new name.';
                errorEl.classList.remove('d-none');
                return;
            }
            if (newName.toLowerCase() === nb.name.toLowerCase()) {
                errorEl.textContent = 'New name is same as the current name.';
                errorEl.classList.remove('d-none');
                return;
            }
            const duplicate = notebooks.find(n => n.id !== nb.id && n.name.toLowerCase() === newName.toLowerCase());
            if (duplicate) {
                errorEl.textContent = `A notebook named "${newName}" already exists.`;
                errorEl.classList.remove('d-none');
                return;
            }

            cleanup();
            bsModal.hide();

            modalEl.addEventListener('hidden.bs.modal', async () => {
                const confirmed = await openVKConfirm({
                    title: 'Confirm Rename',
                    lines: [
                        `Rename <strong>${nb.name}</strong> to <strong>${newName}</strong>?`,
                        'All entries inside will remain unchanged.'
                    ],
                    confirmLabel: 'Yes, Rename',
                    isDanger: false,
                    icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                             <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                             <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                           </svg>`
                });
                resolve(confirmed ? newName : null);
            }, { once: true });
        }

        function onCancel() { cleanup(); resolve(null); }
        function cleanup() {
            nextBtn.removeEventListener('click', onNext);
            modalEl.removeEventListener('hide.bs.modal', onCancel);
        }

        nextBtn.addEventListener('click', onNext);
        modalEl.addEventListener('hide.bs.modal', onCancel, { once: true });
    });
}


// ═════════════════════════════════════════════════════════════
// Entry Password Strength Meter
// ═════════════════════════════════════════════════════════════

async function _getStrengthPrefEnabled() {
    try {
        const res  = await fetch('/api/accounts');
        const data = await res.json();
        const uid  = data.active_user;
        const key  = `vk_prefs_${uid}`;
        const saved = localStorage.getItem(key);
        if (!saved) return true;
        const prefs = JSON.parse(saved);
        return typeof prefs.strength !== 'undefined' ? prefs.strength : true;
    } catch (_) {
        return true;
    }
}

function setupEntryStrengthMeter() {
    const input  = document.getElementById('entry-password');
    const wrap   = document.getElementById('entry-strength-wrap');
    const colors = ['', '#ff5f6d', '#f0a060', '#4f8ef7', '#c8f060'];
    const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];

    input.addEventListener('input', async () => {
        const enabled = await _getStrengthPrefEnabled();
        if (!enabled) { wrap.style.display = 'none'; return; }
        const value = input.value;
        if (!value) { wrap.style.display = 'none'; return; }
        wrap.style.display = 'block';
        let score = 0;
        if (value.length >= 8)           score++;
        if (/[A-Z]/.test(value))         score++;
        if (/[0-9]/.test(value))         score++;
        if (/[^A-Za-z0-9]/.test(value))  score++;
        for (let i = 1; i <= 4; i++) {
            const block = document.getElementById(`entry-sb-${i}`);
            block.style.background = i <= score ? colors[score] : 'var(--border2)';
        }
        const labelEl = document.getElementById('entry-pw-strength-label');
        labelEl.textContent = labels[score] || '';
        labelEl.style.color = colors[score] || 'var(--text3)';
    });
}


// ═════════════════════════════════════════════════════════════
// Multi Account
// ═════════════════════════════════════════════════════════════

async function loadAccounts() {
    try {
        const res  = await fetch('/api/accounts');
        const data = await res.json();
        renderAccountSwitcher(data.accounts, data.active_user);
    } catch (err) {
        console.error('loadAccounts error:', err);
    }
}

function renderAccountSwitcher(accounts, activeUserId) {
    const existing = document.getElementById('acct-switcher-dropdown');
    if (existing) existing.remove();

    const wrap = document.querySelector('.acct-switcher-wrap');
    if (!wrap) return;

    const dropdown = document.createElement('div');
    dropdown.id = 'acct-switcher-dropdown';
    dropdown.className = 'nb-dropdown acct-dropdown';
    dropdown.style.cssText = 'bottom:calc(100% + 6px);top:auto;right:0;left:0;min-width:220px;';

    accounts.forEach(acc => {
        const isActive = acc.user_id === activeUserId;
        const item = document.createElement('button');
        item.className = `nb-menu-item acct-item${isActive ? ' acct-item-active' : ''}`;
        item.innerHTML = `
            <div class="user-avatar" style="
                width:26px;height:26px;font-size:0.7rem;font-weight:800;border-radius:50%;
                background:${isActive ? 'var(--accent)' : 'var(--bg3)'};
                color:${isActive ? '#0a0c10' : 'var(--text2)'};
                display:flex;align-items:center;justify-content:center;flex-shrink:0;
                border:1px solid ${isActive ? 'transparent' : 'var(--border2)'};
            ">${acc.username[0].toUpperCase()}</div>
            <div style="flex:1;min-width:0;text-align:left;">
                <div style="font-size:0.8125rem;font-weight:700;color:${isActive ? 'var(--accent)' : 'var(--text)'};white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                    ${acc.username}
                </div>
                <div style="font-size:0.7rem;color:var(--text3);font-family:var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                    ${acc.email}
                </div>
            </div>
            ${isActive ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>` : ''}
        `;
        if (!isActive) {
            item.addEventListener('click', () => switchAccount(acc.user_id, acc.username));
        }
        dropdown.appendChild(item);
    });

    const div1 = document.createElement('div');
    div1.className = 'nb-menu-divider';
    dropdown.appendChild(div1);

    const addBtn = document.createElement('button');
    addBtn.className = 'nb-menu-item';
    addBtn.innerHTML = `
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
        </svg>
        Add Account
    `;
    addBtn.addEventListener('click', addAccount);
    dropdown.appendChild(addBtn);

    const profileBtn = document.createElement('button');
    profileBtn.className = 'nb-menu-item';
    profileBtn.innerHTML = `
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
            <circle cx="12" cy="7" r="4"/>
        </svg>
        Profile &amp; Settings
    `;
    profileBtn.addEventListener('click', () => {
        closeAccountSwitcher();
        window.location.href = '/profile';
    });
    dropdown.appendChild(profileBtn);

    const div2 = document.createElement('div');
    div2.className = 'nb-menu-divider';
    dropdown.appendChild(div2);

    const outBtn = document.createElement('button');
    outBtn.className = 'nb-menu-item';
    outBtn.innerHTML = `
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
            <polyline points="16 17 21 12 16 7"/>
            <line x1="21" y1="12" x2="9" y2="12"/>
        </svg>
        Sign Out Options
    `;
    outBtn.addEventListener('click', () => {
        closeAccountSwitcher();
        openLogoutModal();
    });
    dropdown.appendChild(outBtn);

    wrap.appendChild(dropdown);
}

function toggleAccountSwitcher(e) {
    e.stopPropagation();
    const dd = document.getElementById('acct-switcher-dropdown');
    if (!dd) return;
    dd.classList.toggle('open');
}

function closeAccountSwitcher() {
    const dd = document.getElementById('acct-switcher-dropdown');
    if (dd) dd.classList.remove('open');
}

async function switchAccount(userId, username) {
    closeAccountSwitcher();
    const res = await fetch('/api/switch-account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId })
    });
    if (!res.ok) { showToast('Failed to switch account', 'error'); return; }

    currentNotebookId = null;
    notebooks = [];
    allEntries = [];

    document.getElementById('section-notebook').classList.add('d-none');
    document.getElementById('section-search').classList.add('d-none');
    document.getElementById('section-home').classList.remove('d-none');
    document.getElementById('notebooks-grid').innerHTML = '<div class="nb-empty">Loading…</div>';
    document.getElementById('notebooks-nav').innerHTML  = '<div class="nav-placeholder">Loading…</div>';
    document.getElementById('entries-list').innerHTML   = '';
    document.getElementById('entry-search').value       = '';
    document.getElementById('topbar-title').textContent = 'Dashboard';

    document.querySelectorAll('.user-name').forEach(el => el.textContent = username);
    document.querySelectorAll('.user-avatar').forEach(el => el.textContent = username[0].toUpperCase());

    await Promise.all([loadStats(), loadNotebooks(), loadAccounts()]);
    showToast(`Switched to ${username}`, 'success');
}

function addAccount() {
    closeAccountSwitcher();
    window.location.href = '/login?add=1';
}

async function logoutCurrent() {
    const res  = await fetch('/api/logout-current', { method: 'POST' });
    const data = await res.json();
    window.location.href = data.new_active_user ? '/dashboard' : '/login';
}

async function logoutAll() {
    await fetch('/api/logout-all', { method: 'POST' });
    window.location.href = '/login';
}

function openLogoutModal() {
    new bootstrap.Modal(document.getElementById('logoutModal')).show();
}


// ── Debounce ──────────────────────────────────────────────────
function debounce(fn, delay) {
    let timer;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); };
}


// ── Notebook Search (sidebar) ─────────────────────────────────
function handleSearch() {
    const query           = document.getElementById('global-search').value.trim().toLowerCase();
    const sectionHome     = document.getElementById('section-home');
    const sectionNotebook = document.getElementById('section-notebook');
    const sectionSearch   = document.getElementById('section-search');

    if (!query) {
        sectionSearch.classList.add('d-none');
        if (currentNotebookId) {
            sectionHome.classList.add('d-none');
            sectionNotebook.classList.remove('d-none');
        } else {
            sectionHome.classList.remove('d-none');
            sectionNotebook.classList.add('d-none');
        }
        return;
    }

    sectionHome.classList.add('d-none');
    sectionNotebook.classList.add('d-none');
    sectionSearch.classList.remove('d-none');

    const matches = notebooks.filter(nb =>
        nb.name.toLowerCase().includes(query) ||
        (nb.description || '').toLowerCase().includes(query)
    );

    const list = document.getElementById('search-results-list');

    if (!matches.length) {
        list.innerHTML = `<div class="entry-empty">No notebooks found for "${query}".</div>`;
        return;
    }

    list.innerHTML = '';
    matches.forEach(nb => {
        const div = document.createElement('div');
        div.className = 'nb-card';
        div.style.setProperty('--nb-color', nb.color);
        div.innerHTML = `
            <div class="nb-card-name">${nb.name}</div>
            <div class="nb-card-desc">${nb.description || ''}</div>
            <div class="nb-card-meta"><span>${nb.entry_count} entries</span></div>
        `;
        div.addEventListener('click', () => {
            document.getElementById('global-search').value = '';
            sectionSearch.classList.add('d-none');
            openNotebook(nb.id, nb.name, nb.color);
        });
        list.appendChild(div);
    });
}


// ── Entry Search (per-notebook) ───────────────────────────────
function filterEntries() {
    const query = document.getElementById('entry-search').value.trim().toLowerCase();
    const list  = document.getElementById('entries-list');

    if (!allEntries.length) return;

    const filtered = query
        ? allEntries.filter(e =>
            e.title.toLowerCase().includes(query) ||
            (e.username || '').toLowerCase().includes(query) ||
            (e.url || '').toLowerCase().includes(query)
          )
        : allEntries;

    if (!filtered.length) {
        list.innerHTML = query
            ? `<div class="entry-empty">No entries found for "${query}".</div>`
            : `<div class="entry-empty">No entries yet. Add your first password.</div>`;
        return;
    }

    list.innerHTML = '';
    filtered.forEach(e => renderEntryCard(e, list));
}


// ── Stats ─────────────────────────────────────────────────────
async function loadStats() {
    const res  = await fetch('/api/stats');
    const data = await res.json();
    document.getElementById('stat-notebooks').textContent = data.notebooks;
    document.getElementById('stat-entries').textContent   = data.entries;
    document.getElementById('stat-since').textContent     = data.member_since;
}


// ── Notebooks ─────────────────────────────────────────────────
async function loadNotebooks() {
    const res = await fetch('/api/notebooks');
    notebooks = await res.json();
    renderNotebooks();
}

function renderNotebooks() {
    const grid = document.getElementById('notebooks-grid');
    const nav  = document.getElementById('notebooks-nav');

    if (notebooks.length === 0) {
        grid.innerHTML = `<div class="nb-empty">No notebooks yet.</div>`;
        nav.innerHTML  = `<div class="nav-placeholder">No notebooks</div>`;
        return;
    }

    grid.innerHTML = '';
    nav.innerHTML  = '';

    notebooks.forEach(nb => {

        // Grid Card
        const card = document.createElement('div');
        card.className = 'nb-card';
        card.style.setProperty('--nb-color', nb.color);
        card.innerHTML = `
            <div class="nb-card-name">${nb.name}</div>
            <div class="nb-card-desc">${nb.description || ''}</div>
            <div class="nb-card-meta"><span>${nb.entry_count} entries</span></div>
        `;
        card.addEventListener('click', () => openNotebook(nb.id, nb.name, nb.color));
        grid.appendChild(card);

        // Sidebar Item
        const item = document.createElement('div');
        item.className    = 'nav-item';
        item.dataset.nbId = nb.id;

        item.innerHTML = `
            <span class="nav-dot" style="background:${nb.color}"></span>
            <span class="nav-label">${nb.name}</span>
            <div class="nb-menu-wrap" style="position:relative;flex-shrink:0;">
                <button class="icon-btn nb-dots-btn" title="Options">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                        <circle cx="12" cy="5" r="2"/>
                        <circle cx="12" cy="12" r="2"/>
                        <circle cx="12" cy="19" r="2"/>
                    </svg>
                </button>
                <div class="nb-dropdown">
                    <button class="nb-menu-item" data-action="open">Open</button>
                    <button class="nb-menu-item" data-action="rename">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                        </svg>
                        Rename
                    </button>
                    <button class="nb-menu-item" data-action="change-color">Change Color</button>
                    <button class="nb-menu-item" data-action="duplicate">Duplicate</button>
                    <div class="nb-menu-divider"></div>
                    <button class="nb-menu-item danger" data-action="delete">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="3 6 5 6 21 6"/>
                            <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                            <path d="M10 11v6"/><path d="M14 11v6"/>
                            <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
                        </svg>
                        Delete
                    </button>
                </div>
            </div>
        `;

        item.addEventListener('click', (e) => {
            if (e.target.closest('.nb-menu-wrap') || e.target.closest('.nb-dropdown')) return;
            openNotebook(nb.id, nb.name, nb.color);
        });

        const dotsBtn  = item.querySelector('.nb-dots-btn');
        const dropdown = item.querySelector('.nb-dropdown');

        dotsBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = dropdown.classList.contains('open');
            document.querySelectorAll('.nb-dropdown').forEach(d => d.classList.remove('open'));
            if (!isOpen) dropdown.classList.add('open');
        });

        dropdown.querySelectorAll('.nb-menu-item').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropdown.classList.remove('open');
                const action = btn.dataset.action;

                if (action === 'open') {
                    openNotebook(nb.id, nb.name, nb.color);
                }

                else if (action === 'rename') {
                    const newName = await openRenameModal(nb);
                    if (!newName) return;

                    const res  = await fetch(`/api/notebooks/${nb.id}`, {
                        method:  'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body:    JSON.stringify({ name: newName })
                    });
                    const data = await res.json();

                    if (res.ok) {
                        await loadNotebooks();
                        if (currentNotebookId === nb.id) {
                            document.getElementById('entries-title').textContent = newName;
                        }
                        showToast('Notebook renamed', 'success');
                    } else {
                        showToast(data.error || 'Failed to rename notebook', 'error');
                    }
                }

                else if (action === 'change-color') {
                    openColorModal(nb);
                }

                else if (action === 'duplicate') {
                    const confirmed = await openVKConfirm({
                        title: 'Duplicate Notebook',
                        lines: [
                            `Create a copy of <strong>${nb.name}</strong>?`,
                            'All entries will be duplicated into the new notebook.'
                        ],
                        confirmLabel: 'Yes, Duplicate',
                        isDanger: false,
                        icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                 <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                 <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                               </svg>`
                    });

                    if (!confirmed) return;

                    const res  = await fetchWithVaultGate(`/api/notebooks/${nb.id}/duplicate`, { method: 'POST' });
                    const data = await res.json();

                    if (res.ok) {
                        await loadNotebooks();
                        showToast('Notebook duplicated', 'success');
                    } else if (!data.locked) {
                        showToast(data.error || 'Failed to duplicate notebook', 'error');
                    }
                }

                else if (action === 'delete') {
                    const entryWord = nb.entry_count === 1 ? '1 entry' : `${nb.entry_count} entries`;

                    const confirmed = await openVKConfirm({
                        title: `Delete "${nb.name}"?`,
                        lines: [
                            `You're about to permanently delete <strong>${nb.name}</strong> and all its contents.`,
                            nb.entry_count > 0
                                ? `This notebook contains <strong>${entryWord}</strong> — they will all be lost.`
                                : 'This notebook is empty.',
                            'This action <strong>cannot be undone</strong>.'
                        ],
                        confirmLabel: 'Yes, Delete',
                        isDanger: true
                    });

                    if (!confirmed) return;

                    const res = await fetch(`/api/notebooks/${nb.id}`, { method: 'DELETE' });

                    if (res.ok) {
                        if (currentNotebookId === nb.id) {
                            currentNotebookId = null;
                            allEntries = [];
                            document.getElementById('entry-search').value = '';
                            document.getElementById('section-notebook').classList.add('d-none');
                            document.getElementById('section-home').classList.remove('d-none');
                        }
                        await loadNotebooks();
                        showToast('Notebook deleted', 'success');
                    } else {
                        showToast('Failed to delete notebook', 'error');
                    }
                }
            });
        });

        nav.appendChild(item);
    });
}


// ── Open Notebook ─────────────────────────────────────────────
function openNotebook(id, name, color) {
    currentNotebookId = id;
    document.getElementById('entry-search').value = '';
    document.getElementById('section-home').classList.add('d-none');
    document.getElementById('section-notebook').classList.remove('d-none');
    document.getElementById('section-search').classList.add('d-none');
    document.getElementById('entries-title').textContent     = name;
    document.getElementById('nb-color-dot').style.background = color;
    document.querySelectorAll('#notebooks-nav .nav-item').forEach(item => {
        item.classList.toggle('active', parseInt(item.dataset.nbId) === id);
    });
    loadEntries(id);
}


// ── Entries ───────────────────────────────────────────────────
async function loadEntries(id) {
    const res     = await fetch(`/api/notebooks/${id}/entries`);
    const entries = await res.json();
    allEntries    = entries;

    const list = document.getElementById('entries-list');

    if (entries.length === 0) {
        list.innerHTML = `<div class="entry-empty">No entries yet.</div>`;
        return;
    }

    list.innerHTML = '';
    entries.forEach(e => renderEntryCard(e, list));
}

function renderEntryCard(e, list) {
    const div = document.createElement('div');
    div.className = 'entry-card';

    div.innerHTML = `
        <div class="entry-icon">${e.title[0]}</div>
        <div class="entry-info">
            <div class="entry-title">${e.title}</div>
            <div class="entry-user">${e.username || ''}</div>
        </div>
        <div class="entry-actions">
            <button class="entry-delete" title="Delete">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="3 6 5 6 21 6"/>
                    <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                    <path d="M10 11v6"/><path d="M14 11v6"/>
                    <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
                </svg>
            </button>
        </div>
    `;

    div.addEventListener('click', (event) => {
        if (event.target.closest('.entry-delete')) return;
        openEntry(e);
    });

    div.querySelector('.entry-delete').addEventListener('click', async (event) => {
        event.stopPropagation();
        await deleteEntry(e);
    });

    list.appendChild(div);
}


// ── Open Entry (edit) ─────────────────────────────────────────
async function openEntry(entry) {
    editingEntryId = entry.id;
    resetEntryForm();

    const oldGroup = document.getElementById('old-password-group');
    if (oldGroup) oldGroup.style.display = 'block';

    document.getElementById('entry-title').value    = entry.title;
    document.getElementById('entry-username').value = entry.username || '';
    document.getElementById('entry-url').value      = entry.url     || '';
    document.getElementById('entry-notes').value    = entry.notes   || '';
    document.getElementById('entry-password').value = '';
    document.getElementById('entry-old-password').value = '';

    try {
        const res  = await fetchWithVaultGate(`/api/entries/${entry.id}/password`);
        const data = await res.json();
        if (res.ok) {
            document.getElementById('entry-old-password').value = data.password;
        }
    } catch (err) {
        console.error(err);
    }

    document.getElementById('entryModalTitle').textContent = 'Edit Entry';
    new bootstrap.Modal(document.getElementById('entryModal')).show();
}


// ── Create / Update Entry ─────────────────────────────────────
async function createOrUpdateEntry() {
    const title    = document.getElementById('entry-title').value.trim();
    const username = document.getElementById('entry-username').value;
    const password = document.getElementById('entry-password').value;
    const url      = document.getElementById('entry-url').value;
    const notes    = document.getElementById('entry-notes').value;

    if (!title) { showToast('Title is required', 'error'); return; }
    if (!editingEntryId && !password) { showToast('Password is required', 'error'); return; }

    // Global duplicate check
    const normalizedTitle = title.toLowerCase();
    let duplicateFound = false;
    for (const nb of notebooks) {
        try {
            const res     = await fetch(`/api/notebooks/${nb.id}/entries`);
            const entries = await res.json();
            const dup = entries.find(entry => {
                if (editingEntryId && entry.id === editingEntryId) return false;
                return entry.title.trim().toLowerCase() === normalizedTitle;
            });
            if (dup) { duplicateFound = true; break; }
        } catch (err) {
            console.error(err);
        }
    }

    if (duplicateFound) { showToast('Entry title already exists', 'error'); return; }

    const endpoint = editingEntryId
        ? `/api/entries/${editingEntryId}`
        : `/api/notebooks/${currentNotebookId}/entries`;

    const res = await fetchWithVaultGate(endpoint, {
        method:  editingEntryId ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ title, username, password, url, notes })
    });

    const data = await res.json();

    if (res.ok) {
        const wasEditing = editingEntryId;
        await loadEntries(currentNotebookId);
        bootstrap.Modal.getInstance(document.getElementById('entryModal')).hide();
        editingEntryId = null;
        resetEntryForm();
        const query = document.getElementById('entry-search').value.trim();
        if (query) filterEntries();
        showToast(wasEditing ? 'Entry updated' : 'Entry created', 'success');
    } else if (!data.locked) {
        showToast(data.error || 'Failed to save entry', 'error');
    }
}


// ── Delete Entry ──────────────────────────────────────────────
async function deleteEntry(entry) {
    const confirmed = await openVKConfirm({
        title: `Delete "${entry.title}"?`,
        lines: [
            `You're about to permanently delete the entry <strong>${entry.title}</strong>.`,
            entry.username ? `Username: <strong>${entry.username}</strong>` : null,
            'This action <strong>cannot be undone</strong>.'
        ].filter(Boolean),
        confirmLabel: 'Yes, Delete',
        isDanger: true
    });

    if (!confirmed) return;

    const res = await fetch(`/api/entries/${entry.id}`, { method: 'DELETE' });

    if (res.ok) {
        await loadEntries(currentNotebookId);
        const query = document.getElementById('entry-search').value.trim();
        if (query) filterEntries();
        showToast('Entry deleted', 'success');
    } else {
        showToast('Failed to delete entry', 'error');
    }
}


// ── Reset Form ────────────────────────────────────────────────
function resetEntryForm() {
    ['entry-title', 'entry-username', 'entry-password', 'entry-url', 'entry-notes'].forEach(id => {
        document.getElementById(id).value = '';
    });
    const oldPw = document.getElementById('entry-old-password');
    if (oldPw) oldPw.value = '';
    for (let i = 1; i <= 4; i++) {
        const block = document.getElementById(`entry-sb-${i}`);
        if (block) block.style.background = 'var(--border2)';
    }
    const labelEl = document.getElementById('entry-pw-strength-label');
    if (labelEl) labelEl.textContent = '';
    const wrap = document.getElementById('entry-strength-wrap');
    if (wrap) wrap.style.display = 'none';
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


// ── Create Notebook ───────────────────────────────────────────
async function createNotebook() {
    const name   = document.getElementById('nb-name').value.trim();
    const desc   = document.getElementById('nb-desc').value.trim();
    const swatch = document.querySelector('#color-picker .color-swatch.active');
    const color  = swatch ? swatch.dataset.color : '#4f8ef7';

    if (!name) { document.getElementById('nb-name').focus(); return; }

    const normalizedName = name.toLowerCase();
    const duplicate = notebooks.find(nb => nb.name.trim().toLowerCase() === normalizedName);
    if (duplicate) { showToast('Notebook name already exists', 'error'); return; }

    const res = await fetch('/api/notebooks', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ name, description: desc, color })
    });
    const data = await res.json();

    if (res.ok) {
        document.getElementById('nb-name').value = '';
        document.getElementById('nb-desc').value = '';
        bootstrap.Modal.getInstance(document.getElementById('notebookModal')).hide();
        await loadNotebooks();
        showToast('Notebook created', 'success');
    } else {
        showToast(data.error || 'Failed to create notebook', 'error');
    }
}


// ── Color Modal ───────────────────────────────────────────────
function openColorModal(nb) {
    const colors = ['#4f8ef7', '#c8f060', '#f06090', '#f0a060', '#60d4f0', '#a060f0'];

    const overlay = document.createElement('div');
    overlay.className = 'color-modal-overlay';
    overlay.innerHTML = `
        <div class="color-modal-box">
            <div class="color-modal-title">Change Color — ${nb.name}</div>
            <div class="color-picker" id="cm-picker" style="margin-bottom:1.25rem;">
                ${colors.map(c => `
                    <div class="color-swatch ${c === nb.color ? 'active' : ''}"
                         data-color="${c}" style="background:${c};"></div>
                `).join('')}
            </div>
            <div style="display:flex;gap:0.75rem;justify-content:flex-end;">
                <button class="btn-cancel" id="cm-cancel">Cancel</button>
                <button class="btn-confirm" id="cm-save">Save</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector('#cm-picker').addEventListener('click', (e) => {
        const swatch = e.target.closest('.color-swatch');
        if (!swatch) return;
        overlay.querySelectorAll('.color-swatch').forEach(s => s.classList.remove('active'));
        swatch.classList.add('active');
    });

    overlay.querySelector('#cm-cancel').addEventListener('click', () => document.body.removeChild(overlay));

    overlay.querySelector('#cm-save').addEventListener('click', async () => {
        const active   = overlay.querySelector('.color-swatch.active');
        const newColor = active ? active.dataset.color : nb.color;
        const res = await fetch(`/api/notebooks/${nb.id}`, {
            method:  'PUT',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ color: newColor })
        });
        document.body.removeChild(overlay);
        if (res.ok) {
            await loadNotebooks();
            if (currentNotebookId === nb.id) {
                document.getElementById('nb-color-dot').style.background = newColor;
            }
            showToast('Color updated', 'success');
        } else {
            showToast('Failed to update color', 'error');
        }
    });
}