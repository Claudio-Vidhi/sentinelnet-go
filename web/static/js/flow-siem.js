// ===== Flow SIEM & Active Threat Defense =====

let currentSiemSubTab = 'events'; // 'events' | 'facets' | 'shun'
let siemAutoRefreshInterval = null;

async function loadFlowSiemTab() {
    initSiemTenants();
    if (currentSiemSubTab === 'facets') {
        loadSiemFacets();
    } else if (currentSiemSubTab === 'shun') {
        loadShunList();
    } else {
        loadSiemEvents();
        loadSiemHistogram();
    }
}

function switchSiemSubTab(subTab) {
    currentSiemSubTab = subTab;
    document.querySelectorAll('.siem-subnav-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.subtab === subTab);
    });
    document.getElementById('siemSubViewEvents').style.display = subTab === 'events' ? 'block' : 'none';
    document.getElementById('siemSubViewFacets').style.display = subTab === 'facets' ? 'block' : 'none';
    document.getElementById('siemSubViewShun').style.display = subTab === 'shun' ? 'block' : 'none';
    loadFlowSiemTab();
}

function initSiemTenants() {
    const sel = document.getElementById('siemTenantSelect');
    if (!sel || sel.options.length > 1) return;
    const groups = Object.keys(globalGroups || {});
    groups.forEach(g => {
        const opt = document.createElement('option');
        opt.value = g;
        opt.textContent = g;
        sel.appendChild(opt);
    });
}

async function loadSiemEvents() {
    const tbody = document.getElementById('siemEventsTableBody');
    if (tbody) {
        tbody.innerHTML = `<tr><td colspan="7" style="padding:20px; text-align:center; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin"></i> Caricamento eventi di sicurezza...</td></tr>`;
    }

    const windowVal = document.getElementById('siemWindowSelect') ? document.getElementById('siemWindowSelect').value : '24h';
    const actionVal = document.getElementById('siemActionFilter') ? document.getElementById('siemActionFilter').value : '';
    const tenantVal = document.getElementById('siemTenantSelect') ? document.getElementById('siemTenantSelect').value : 'all';
    const queryVal = document.getElementById('siemSearchInput') ? document.getElementById('siemSearchInput').value.trim() : '';

    let url = `/api/flow-siem/events?window=${encodeURIComponent(windowVal)}&limit=100`;
    if (actionVal) url += `&action=${encodeURIComponent(actionVal)}`;
    if (tenantVal && tenantVal !== 'all') url += `&tenant=${encodeURIComponent(tenantVal)}`;
    if (queryVal) url += `&q=${encodeURIComponent(queryVal)}`;

    try {
        const res = await apiFetch(url);
        if (!res || !res.ok) {
            if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="padding:16px; text-align:center; color:var(--danger);">Errore nel recupero degli eventi SIEM.</td></tr>`;
            return;
        }
        const data = await res.json();
        renderSiemEventsTable(data.events || []);
    } catch (e) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="padding:16px; text-align:center; color:var(--danger);">${escapeHtml(e.message)}</td></tr>`;
    }
}

function renderSiemEventsTable(events) {
    const tbody = document.getElementById('siemEventsTableBody');
    if (!tbody) return;
    if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="padding:24px; text-align:center; color:var(--text-muted);"><i class="fa-solid fa-shield-halved" style="color:var(--success); margin-right:6px;"></i> Nessun evento di minaccia o blocco nel periodo selezionato.</td></tr>`;
        return;
    }

    tbody.innerHTML = events.map(ev => {
        const dt = ev.ts ? new Date(ev.ts * 1000).toLocaleTimeString() : '—';
        const isDeny = ev.is_deny || (ev.action && ['deny', 'drop', 'blocked', 'block', 'reject'].includes(ev.action.toLowerCase()));
        const actBadge = isDeny ?
            `<span class="status bad"><span class="led led-danger"></span>${escapeHtml(ev.action || 'DENY')}</span>` :
            `<span class="status ok"><span class="led led-success"></span>${escapeHtml(ev.action || 'ACCEPT')}</span>`;

        const threatChip = ev.threat_flag ? `<span class="chip" style="background:rgba(250, 127, 170, 0.2); color:var(--danger); border-color:var(--danger);">${escapeHtml(ev.threat_flag)}</span>` : '<span style="color:var(--text-muted);">—</span>';

        return `<tr>
            <td style="font-size:11px; color:var(--text-muted); white-space:nowrap;">${escapeHtml(dt)}</td>
            <td>${actBadge}</td>
            <td><code style="color:var(--danger);">${escapeHtml(ev.src_ip || '—')}</code></td>
            <td><code>${escapeHtml(ev.dst_ip || '—')}</code></td>
            <td><span class="badge" style="font-size:11px;">${escapeHtml(ev.proto || 'IP')}</span></td>
            <td>${threatChip}</td>
            <td>
                <div style="display:flex; gap:6px; align-items:center;">
                    ${ev.src_ip ? `<button class="btn btn-secondary btn-small" onclick="promptShunIP('${escapeHtml(ev.src_ip)}')" style="color:var(--danger); border-color:var(--danger);" title="Blocca/Shun IP"><i class="fa-solid fa-ban"></i> Shun</button>` : ''}
                    <button class="btn btn-secondary btn-small" onclick="suppressSiemAlert(${ev.id})" title="Sopprimi allerta (falso positivo)"><i class="fa-solid fa-bell-slash"></i></button>
                </div>
            </td>
        </tr>`;
    }).join('');
}

async function loadSiemHistogram() {
    const box = document.getElementById('siemHistogramBars');
    if (!box) return;

    const windowVal = document.getElementById('siemWindowSelect') ? document.getElementById('siemWindowSelect').value : '24h';
    const tenantVal = document.getElementById('siemTenantSelect') ? document.getElementById('siemTenantSelect').value : 'all';

    let url = `/api/flow-siem/histogram?window=${encodeURIComponent(windowVal)}&buckets=28`;
    if (tenantVal && tenantVal !== 'all') url += `&tenant=${encodeURIComponent(tenantVal)}`;

    try {
        const res = await apiFetch(url);
        if (!res || !res.ok) return;
        const data = await res.json();
        const buckets = data.buckets || [];
        renderSiemHistogram(buckets);
    } catch (e) {
        console.error('Histogram fetch error:', e);
    }
}

function renderSiemHistogram(buckets) {
    const box = document.getElementById('siemHistogramBars');
    if (!box) return;
    if (buckets.length === 0) {
        box.innerHTML = `<div style="text-align:center; width:100%; color:var(--text-muted); font-size:12px; padding:20px;">Nessun dato traffico per l'istogramma.</div>`;
        return;
    }

    let maxVal = 1;
    buckets.forEach(b => {
        if (b.count > maxVal) maxVal = b.count;
    });

    box.innerHTML = buckets.map(b => {
        const totalHeightPct = Math.max(4, Math.round((b.count / maxVal) * 100));
        const denyHeightPct = b.count > 0 ? Math.round((b.deny_count / b.count) * 100) : 0;

        return `<div class="siem-hist-col" title="${escapeHtml(b.timestamp)}: ${b.count} tot, ${b.deny_count} negati">
            <div class="siem-hist-bar" style="height:${totalHeightPct}%;">
                <div class="siem-hist-deny" style="height:${denyHeightPct}%;"></div>
            </div>
            <span class="siem-hist-label">${escapeHtml(b.timestamp)}</span>
        </div>`;
    }).join('');
}

async function loadSiemFacets() {
    const box = document.getElementById('siemFacetsContainer');
    if (!box) return;
    box.innerHTML = `<div style="text-align:center; padding:30px;"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><p style="margin-top:10px; color:var(--text-muted);">Calcolo aggregazioni di sicurezza e top talker...</p></div>`;

    const windowVal = document.getElementById('siemWindowSelect') ? document.getElementById('siemWindowSelect').value : '24h';
    const tenantVal = document.getElementById('siemTenantSelect') ? document.getElementById('siemTenantSelect').value : 'all';

    let url = `/api/flow-siem/facets?window=${encodeURIComponent(windowVal)}`;
    if (tenantVal && tenantVal !== 'all') url += `&tenant=${encodeURIComponent(tenantVal)}`;

    try {
        const res = await apiFetch(url);
        if (!res || !res.ok) {
            box.innerHTML = `<div class="alert-box alert-danger">Impossibile calcolare i facets SIEM.</div>`;
            return;
        }
        const data = await res.json();
        renderSiemFacets(data);
    } catch (e) {
        box.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(e.message)}</div>`;
    }
}

function renderSiemFacets(data) {
    const box = document.getElementById('siemFacetsContainer');
    if (!box) return;

    const renderList = (items, colorVar) => {
        if (!items || items.length === 0) return `<div style="color:var(--text-muted); font-size:12px; padding:10px;">Nessun dato.</div>`;
        return items.map(item => `
            <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid rgba(255,255,255,0.05); font-size:13px;">
                <code style="color:${colorVar || 'var(--text)'};">${escapeHtml(item.value || 'N/D')}</code>
                <strong style="font-family:var(--font-display);">${item.count}</strong>
            </div>
        `).join('');
    };

    box.innerHTML = `
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); gap:18px;">
            <div class="panel">
                <h4 style="margin:0 0 12px; font-size:14px; color:var(--danger);"><i class="fa-solid fa-skull-crossbones"></i> Top IP Sorgenti / Attaccanti</h4>
                ${renderList(data.top_src_ips, 'var(--danger)')}
            </div>
            <div class="panel">
                <h4 style="margin:0 0 12px; font-size:14px; color:var(--warning);"><i class="fa-solid fa-bullseye"></i> Top Destinazioni Bersaglio</h4>
                ${renderList(data.top_dst_ips, 'var(--warning)')}
            </div>
            <div class="panel">
                <h4 style="margin:0 0 12px; font-size:14px; color:var(--primary);"><i class="fa-solid fa-shield-virus"></i> Minacce / Flag Rilevati</h4>
                ${renderList(data.threat_flags, 'var(--primary)')}
            </div>
            <div class="panel">
                <h4 style="margin:0 0 12px; font-size:14px; color:var(--text);"><i class="fa-solid fa-traffic-light"></i> Azioni Firewall</h4>
                ${renderList(data.actions, 'var(--text)')}
            </div>
        </div>
    `;
}

// ===== Shun IP (Active Defense) =====

async function promptShunIP(ip) {
    const reason = prompt(`Inserisci il motivo del blocco/shun per l'indirizzo ${ip}:`, 'Rilevata attività anomala/malevola via SIEM');
    if (reason === null) return;

    try {
        const res = await apiFetch('/api/flow-siem/shun-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, reason: reason })
        });
        if (!res || !res.ok) {
            showToast(`Errore durante lo shun dell'IP ${ip}`, 'error');
            return;
        }
        showToast(`IP ${ip} aggiunto alla shun-list con successo!`, 'ok');
        if (currentSiemSubTab === 'shun') loadShunList();
    } catch (e) {
        showToast('Errore: ' + e.message, 'error');
    }
}

async function loadShunList() {
    const tbody = document.getElementById('siemShunTableBody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="5" style="padding:20px; text-align:center; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin"></i> Caricamento shun list...</td></tr>`;

    try {
        const res = await apiFetch('/api/flow-siem/shun-list');
        if (!res || !res.ok) {
            tbody.innerHTML = `<tr><td colspan="5" style="padding:16px; text-align:center; color:var(--danger);">Impossibile caricare la shun list.</td></tr>`;
            return;
        }
        const data = await res.json();
        const items = data.shunned_ips || [];
        renderShunListTable(items);
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" style="padding:16px; text-align:center; color:var(--danger);">${escapeHtml(e.message)}</td></tr>`;
    }
}

function renderShunListTable(items) {
    const tbody = document.getElementById('siemShunTableBody');
    if (!tbody) return;
    if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="padding:24px; text-align:center; color:var(--text-muted);"><i class="fa-solid fa-check-circle" style="color:var(--success); margin-right:6px;"></i> Nessun indirizzo IP attualmente bloccato nella shun-list.</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(item => {
        const dt = item.ts ? new Date(item.ts * 1000).toLocaleString() : '—';
        return `<tr>
            <td><code style="color:var(--danger); font-weight:700; font-size:13px;">${escapeHtml(item.ip)}</code></td>
            <td>${escapeHtml(item.reason || '—')}</td>
            <td><span class="badge">${escapeHtml(item.by || 'system')}</span></td>
            <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(dt)}</td>
            <td><span class="status bad"><span class="led led-danger"></span>BLOCKED</span></td>
        </tr>`;
    }).join('');
}

async function suppressSiemAlert(eventId) {
    const reason = prompt('Inserisci il motivo della soppressione (falso positivo):', 'Falso positivo confermato');
    if (reason === null) return;

    try {
        const res = await apiFetch('/api/flow-siem/alerts/suppress', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ event_id: eventId, reason: reason })
        });
        if (!res || !res.ok) {
            showToast('Errore durante la soppressione dell\'allerta', 'error');
            return;
        }
        showToast('Allerta soppressa con successo.', 'ok');
        loadSiemEvents();
    } catch (e) {
        showToast('Errore: ' + e.message, 'error');
    }
}
