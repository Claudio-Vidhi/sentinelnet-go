// ===== NetSec Audit & Compliance Scanner & Checklist Framework =====

let currentNetsecSubTab = 'scanner'; // 'scanner' | 'history' | 'checklist'
let currentEngagementId = null;

async function loadNetSecAuditTab() {
    initAuditDeviceSelect();
    if (currentNetsecSubTab === 'history') {
        loadAuditHistory();
    } else if (currentNetsecSubTab === 'checklist') {
        loadAuditEngagements();
    } else {
        loadAuditBenchmarks();
    }
}

function switchNetsecSubTab(subTab) {
    currentNetsecSubTab = subTab;
    document.querySelectorAll('.netsec-subnav-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.subtab === subTab);
    });
    document.getElementById('netsecSubViewScanner').style.display = subTab === 'scanner' ? 'block' : 'none';
    document.getElementById('netsecSubViewHistory').style.display = subTab === 'history' ? 'block' : 'none';
    document.getElementById('netsecSubViewChecklist').style.display = subTab === 'checklist' ? 'block' : 'none';
    loadNetSecAuditTab();
}

function initAuditDeviceSelect() {
    const sel = document.getElementById('auditDeviceSelect');
    if (!sel || sel.options.length > 2) return;
    const devs = globalDevices || [];
    devs.forEach(d => {
        const opt = document.createElement('option');
        opt.value = d.IP;
        opt.textContent = `${d.Hostname || d.IP} (${d.IP}) - ${d.Vendor || 'cisco'}`;
        sel.appendChild(opt);
    });
}

async function loadAuditBenchmarks() {
    const sel = document.getElementById('auditBenchmarkSelect');
    if (!sel) return;

    try {
        const res = await apiFetch(`/api/netsec-audit/benchmarks?lang=${currentLang || 'it'}`);
        if (!res || !res.ok) return;
        const data = await res.json();
        sel.innerHTML = '';
        Object.keys(data).forEach(bmKey => {
            const opt = document.createElement('option');
            opt.value = bmKey;
            opt.textContent = bmKey.toUpperCase().replace(/_/g, ' ');
            sel.appendChild(opt);
        });
    } catch (e) {
        console.error('Error loading benchmarks:', e);
    }
}

async function runNetSecAuditScan() {
    const devIp = document.getElementById('auditDeviceSelect') ? document.getElementById('auditDeviceSelect').value : '';
    const bm = document.getElementById('auditBenchmarkSelect') ? document.getElementById('auditBenchmarkSelect').value : '';
    const runName = document.getElementById('auditRunName') ? document.getElementById('auditRunName').value.trim() : '';
    const saveRun = document.getElementById('auditSaveRun') ? document.getElementById('auditSaveRun').checked : true;
    const resultsBox = document.getElementById('auditScanResults');
    const btn = document.getElementById('btnRunAuditScan');

    if (!devIp) {
        showToast('Seleziona un dispositivo per la scansione di conformità', 'warning');
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Scansione in corso...`;
    }
    if (resultsBox) {
        resultsBox.style.display = 'block';
        resultsBox.innerHTML = `<div style="text-align:center; padding:30px;"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><p style="margin-top:10px; color:var(--text-muted);">Esecuzione controlli di sicurezza e conformità...</p></div>`;
    }

    try {
        const res = await apiFetch('/api/netsec-audit/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                device_ip: devIp,
                benchmark: bm,
                lang: currentLang || 'it',
                save: saveRun,
                run_name: runName
            })
        });

        if (!res || !res.ok) {
            const err = await res.json();
            if (resultsBox) resultsBox.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(err.detail || 'Errore durante la scansione')}</div>`;
            return;
        }

        const data = await res.json();
        renderAuditScanResults(data);
    } catch (e) {
        if (resultsBox) resultsBox.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(e.message)}</div>`;
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> Esegui Scansione Conformità`;
        }
    }
}

function renderAuditScanResults(data) {
    const box = document.getElementById('auditScanResults');
    if (!box) return;

    const score = data.score !== undefined ? data.score : 100;
    const scoreColor = score >= 85 ? 'var(--success)' : (score >= 65 ? 'var(--warning)' : 'var(--danger)');
    const findings = data.findings || [];

    const passedCount = findings.filter(f => f.status === 'PASS' || f.passed).length;
    const failedCount = findings.filter(f => f.status === 'FAIL' || !f.passed).length;

    const findingsHtml = findings.map(f => {
        const isPass = f.status === 'PASS' || f.passed;
        const stBadge = isPass ?
            `<span class="status ok"><span class="led led-success"></span>PASS</span>` :
            `<span class="status bad"><span class="led led-danger"></span>FAIL</span>`;
        const sevClass = (f.severity || '').toLowerCase() === 'high' ? 'bad' : ((f.severity || '').toLowerCase() === 'medium' ? 'warn' : 'ok');

        return `
            <div style="padding:12px; border-bottom:1px solid var(--border); background:var(--surface-2); border-radius:8px; margin-bottom:8px;">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:6px;">
                    <div>
                        <strong style="font-size:13px; color:var(--text);">${escapeHtml(f.title || f.id)}</strong>
                        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">Ref: ${escapeHtml(f.ref || f.id || '')} | Cat: ${escapeHtml(f.category || 'General')}</div>
                    </div>
                    <div style="display:flex; gap:6px; align-items:center;">
                        <span class="status ${sevClass}" style="font-size:11px;">${escapeHtml(f.severity || 'LOW')}</span>
                        ${stBadge}
                    </div>
                </div>
                ${f.description ? `<p style="margin:4px 0 8px; font-size:12px; color:var(--text-muted); line-height:1.4;">${escapeHtml(f.description)}</p>` : ''}
                ${f.remediation ? `
                <div style="background:var(--surface); border-left:3px solid var(--primary); padding:6px 10px; border-radius:4px; font-size:12px; margin-top:6px;">
                    <span style="color:var(--primary); font-weight:600;"><i class="fa-solid fa-wrench"></i> Rimedio:</span>
                    <pre style="margin:4px 0 0; font-family:var(--font-code); font-size:11px; color:var(--text);">${escapeHtml(f.remediation)}</pre>
                </div>` : ''}
            </div>
        `;
    }).join('') || `<div style="color:var(--text-muted); padding:16px;">Nessun finding registrato.</div>`;

    box.innerHTML = `
        <div class="panel" style="margin-top:18px;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px; margin-bottom:18px; border-bottom:1px solid var(--border); padding-bottom:14px;">
                <div>
                    <h3 style="margin:0 0 4px; font-size:18px;"><i class="fa-solid fa-square-poll-vertical" style="color:var(--primary);"></i> Risultato Audit di Sicurezza</h3>
                    <span style="color:var(--text-muted); font-size:12px;">Dispositivo: <strong>${escapeHtml(data.device_name || data.device_ip || '')}</strong> | Benchmark: <strong>${escapeHtml(data.benchmark || '')}</strong></span>
                </div>
                <div style="display:flex; align-items:center; gap:18px;">
                    <div style="text-align:right;">
                        <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase;">Score di Conformità</div>
                        <strong style="font-family:var(--font-display); font-size:28px; color:${scoreColor};">${score}%</strong>
                    </div>
                </div>
            </div>

            <div style="display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:12px; margin-bottom:18px;">
                <div class="kpi" style="padding:10px 14px;">
                    <h4 style="font-size:11px; margin-bottom:2px;">Controlli Totali</h4>
                    <strong style="font-size:18px;">${findings.length}</strong>
                </div>
                <div class="kpi" style="padding:10px 14px;">
                    <h4 style="font-size:11px; margin-bottom:2px;">Superati (Pass)</h4>
                    <strong style="font-size:18px; color:var(--success);">${passedCount}</strong>
                </div>
                <div class="kpi" style="padding:10px 14px;">
                    <h4 style="font-size:11px; margin-bottom:2px;">Non Conformi (Fail)</h4>
                    <strong style="font-size:18px; color:var(--danger);">${failedCount}</strong>
                </div>
            </div>

            <h4 style="margin:0 0 12px; font-size:14px;"><i class="fa-solid fa-list-check"></i> Dettaglio Controlli</h4>
            <div style="max-height:480px; overflow-y:auto;">${findingsHtml}</div>
        </div>
    `;
}

// ===== Audit Run History =====

async function loadAuditHistory() {
    const tbody = document.getElementById('auditHistoryTableBody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="7" style="padding:20px; text-align:center; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin"></i> Caricamento storico audit...</td></tr>`;

    try {
        const res = await apiFetch('/api/netsec-audit/history');
        if (!res || !res.ok) {
            tbody.innerHTML = `<tr><td colspan="7" style="padding:16px; text-align:center; color:var(--danger);">Impossibile caricare lo storico.</td></tr>`;
            return;
        }
        const data = await res.json();
        const runs = data.runs || [];
        renderAuditHistoryTable(runs);
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" style="padding:16px; text-align:center; color:var(--danger);">${escapeHtml(e.message)}</td></tr>`;
    }
}

function renderAuditHistoryTable(runs) {
    const tbody = document.getElementById('auditHistoryTableBody');
    if (!tbody) return;
    if (runs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="padding:24px; text-align:center; color:var(--text-muted);"><i class="fa-solid fa-box-archive" style="margin-right:6px;"></i> Nessuna scansione registrata nello storico.</td></tr>`;
        return;
    }

    tbody.innerHTML = runs.map(r => {
        const dt = r.ts ? new Date(r.ts * 1000).toLocaleString() : '—';
        const sc = r.score !== null && r.score !== undefined ? `${r.score}%` : 'N/D';
        const scColor = r.score >= 85 ? 'var(--success)' : (r.score >= 65 ? 'var(--warning)' : 'var(--danger)');

        return `<tr>
            <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(dt)}</td>
            <td><strong>${escapeHtml(r.run_name || `Audit #${r.id}`)}</strong></td>
            <td><code>${escapeHtml(r.device_name || r.device_ip || '—')}</code></td>
            <td><span class="chip">${escapeHtml(r.benchmark || 'CIS')}</span></td>
            <td><strong style="color:${scColor};">${sc}</strong></td>
            <td><span class="badge">${escapeHtml(r.actor || 'admin')}</span></td>
            <td>
                <div style="display:flex; gap:6px;">
                    <button class="btn btn-secondary btn-small" onclick="viewAuditHistoryDetail(${r.id})" title="Visualizza report"><i class="fa-solid fa-eye"></i></button>
                    ${currentRole === 'admin' ? `
                    <button class="btn btn-secondary btn-small" onclick="deleteAuditHistoryRun(${r.id})" style="color:var(--danger);" title="Elimina run"><i class="fa-solid fa-trash"></i></button>` : ''}
                </div>
            </td>
        </tr>`;
    }).join('');
}

async function viewAuditHistoryDetail(runId) {
    switchNetsecSubTab('scanner');
    const resultsBox = document.getElementById('auditScanResults');
    if (resultsBox) {
        resultsBox.style.display = 'block';
        resultsBox.innerHTML = `<div style="text-align:center; padding:30px;"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><p style="margin-top:10px; color:var(--text-muted);">Caricamento dettaglio run #${runId}...</p></div>`;
    }

    try {
        const res = await apiFetch(`/api/netsec-audit/history/${runId}`);
        if (!res || !res.ok) return;
        const data = await res.json();
        renderAuditScanResults(data);
    } catch (e) {
        if (resultsBox) resultsBox.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(e.message)}</div>`;
    }
}

async function deleteAuditHistoryRun(runId) {
    if (!confirm(`Sei sicuro di voler eliminare la scansione di audit #${runId}?`)) return;

    try {
        const res = await apiFetch(`/api/netsec-audit/history/${runId}`, { method: 'DELETE' });
        if (!res || !res.ok) {
            showToast('Impossibile eliminare il report di audit', 'error');
            return;
        }
        showToast('Scansione eliminata con successo.', 'ok');
        loadAuditHistory();
    } catch (e) {
        showToast('Errore: ' + e.message, 'error');
    }
}

// ===== Audit Checklist Engagements =====

async function loadAuditEngagements() {
    const container = document.getElementById('checklistEngagementsContainer');
    if (!container) return;
    container.innerHTML = `<div style="text-align:center; padding:30px;"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><p style="margin-top:10px; color:var(--text-muted);">Caricamento audit engagement attivi...</p></div>`;

    try {
        const res = await apiFetch('/api/audit-checklist/engagements');
        if (!res || !res.ok) {
            container.innerHTML = `<div class="alert-box alert-danger">Impossibile caricare gli audit checklist engagements.</div>`;
            return;
        }
        const engs = await res.json();
        renderAuditEngagementsList(engs || []);
    } catch (e) {
        container.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(e.message)}</div>`;
    }
}

function renderAuditEngagementsList(engs) {
    const container = document.getElementById('checklistEngagementsContainer');
    if (!container) return;

    if (engs.length === 0) {
        container.innerHTML = `
            <div class="panel" style="text-align:center; padding:40px;">
                <i class="fa-solid fa-clipboard-check" style="font-size:36px; color:var(--text-muted); margin-bottom:12px;"></i>
                <h3 style="margin-bottom:8px;">Nessun engagement di audit attivo</h3>
                <p style="color:var(--text-muted); font-size:13px; max-width:480px; margin:0 auto 16px;">
                    Crea un nuovo engagement per condurre un assessment di conformità (ISO 27001, NIS2, PCI-DSS, Network Hardening).
                </p>
                <button class="btn btn-primary" onclick="openCreateEngagementModal()" style="width:auto; margin:0 auto;">
                    <i class="fa-solid fa-plus"></i> Nuovo Engagement
                </button>
            </div>
        `;
        return;
    }

    container.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
            <h3 style="margin:0; font-size:16px;"><i class="fa-solid fa-clipboard-list"></i> Engagement di Audit</h3>
            <button class="btn btn-primary btn-small" onclick="openCreateEngagementModal()" style="width:auto;">
                <i class="fa-solid fa-plus"></i> Nuovo Engagement
            </button>
        </div>
        <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(320px, 1fr)); gap:16px;">
            ${engs.map(e => `
                <div class="panel" style="cursor:pointer;" onclick="openEngagementDetail(${e.id})">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
                        <h4 style="margin:0; font-size:15px; color:var(--primary);">${escapeHtml(e.customer_name || 'Cliente')}</h4>
                        <span class="chip">${escapeHtml(e.status || 'in_progress')}</span>
                    </div>
                    <p style="font-size:12px; color:var(--text-muted); margin:0 0 10px;">${escapeHtml(e.scope_notes || 'Nessuna nota')}</p>
                    <div style="font-size:11px; color:var(--text-muted); border-top:1px solid rgba(255,255,255,0.05); padding-top:8px;">
                        Assegnato a: <strong>${escapeHtml(e.assigned_to || 'admin')}</strong> | Tenant: <strong>${escapeHtml(e.tenant || 'default')}</strong>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

function openCreateEngagementModal() {
    const modal = document.getElementById('createEngagementModal');
    if (modal) modal.style.display = 'flex';
}

function closeCreateEngagementModal() {
    const modal = document.getElementById('createEngagementModal');
    if (modal) modal.style.display = 'none';
}

async function submitCreateEngagement() {
    const customer = document.getElementById('engCustomer') ? document.getElementById('engCustomer').value.trim() : '';
    const tenant = document.getElementById('engTenant') ? document.getElementById('engTenant').value : 'default';
    const notes = document.getElementById('engNotes') ? document.getElementById('engNotes').value.trim() : '';

    if (!customer) {
        showToast('Inserisci il nome del cliente o dell\'azienda', 'warning');
        return;
    }

    try {
        const res = await apiFetch('/api/audit-checklist/engagements', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                customer_name: customer,
                tenant: tenant,
                site_id: 'central',
                template_id: 1,
                assigned_to: currentUsername || 'admin',
                scope_notes: notes,
                onsite_or_remote: 'remote',
                interviewee: ''
            })
        });

        if (!res || !res.ok) {
            showToast('Errore durante la creazione dell\'engagement', 'error');
            return;
        }
        showToast('Engagement creato con successo!', 'ok');
        closeCreateEngagementModal();
        loadAuditEngagements();
    } catch (e) {
        showToast('Errore: ' + e.message, 'error');
    }
}
