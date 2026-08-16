// ===== Incident Management & Correlation Engine =====

let currentIncidentId = null;
let currentIncidentSubTab = 'active'; // 'active' | 'rules' | 'suppression'

async function loadIncidentsTab() {
    if (currentIncidentSubTab === 'rules') {
        loadCorrelationRules();
    } else if (currentIncidentSubTab === 'suppression') {
        loadInterfaceSuppressions();
    } else {
        loadIncidentsList();
    }
}

function switchIncidentSubTab(subTab) {
    currentIncidentSubTab = subTab;
    document.querySelectorAll('.inc-subnav-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.subtab === subTab);
    });
    document.getElementById('incSubViewActive').style.display = subTab === 'active' ? 'block' : 'none';
    document.getElementById('incSubViewRules').style.display = subTab === 'rules' ? 'block' : 'none';
    document.getElementById('incSubViewSuppression').style.display = subTab === 'suppression' ? 'block' : 'none';
    loadIncidentsTab();
}

async function loadIncidentsList() {
    const status = document.getElementById('incStatusFilter') ? document.getElementById('incStatusFilter').value : 'new';
    const windowVal = document.getElementById('incWindowFilter') ? document.getElementById('incWindowFilter').value : '24h';
    const tbody = document.getElementById('incidentsTableBody');
    if (tbody) {
        tbody.innerHTML = `<tr><td colspan="7" style="padding:24px; text-align:center; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin"></i> Caricamento incidenti in corso...</td></tr>`;
    }

    try {
        const res = await apiFetch(`/api/incidents?status=${encodeURIComponent(status)}&window=${encodeURIComponent(windowVal)}`);
        if (!res || !res.ok) {
            if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="padding:20px; text-align:center; color:var(--danger);"><i class="fa-solid fa-triangle-exclamation"></i> Errore nel caricamento degli incidenti.</td></tr>`;
            return;
        }
        const data = await res.json();
        const items = data.incidents || [];
        renderIncidentsTable(items);
        updateIncidentsStats(items);
    } catch (e) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="padding:20px; text-align:center; color:var(--danger);">${escapeHtml(e.message)}</td></tr>`;
    }
}

function updateIncidentsStats(items) {
    let crit = 0, high = 0, med = 0, low = 0;
    items.forEach(i => {
        const s = (i.severity || '').toLowerCase();
        if (s === 'critical') crit++;
        else if (s === 'high') high++;
        else if (s === 'medium') med++;
        else low++;
    });
    const setText = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    setText('incKpiTotal', items.length);
    setText('incKpiCritical', crit);
    setText('incKpiHigh', high);
    setText('incKpiWarning', med + low);
}

function renderIncidentsTable(items) {
    const tbody = document.getElementById('incidentsTableBody');
    if (!tbody) return;
    if (!items || items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="padding:24px; text-align:center; color:var(--text-muted);"><i class="fa-solid fa-shield-check" style="color:var(--success); margin-right:6px;"></i> Nessun incidente rilevato nel periodo selezionato.</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(inc => {
        const sev = (inc.severity || 'low').toLowerCase();
        const sevBadge = `<span class="status ${sev === 'critical' || sev === 'high' ? 'bad' : (sev === 'medium' ? 'warn' : 'ok')}"><span class="led ${sev === 'critical' ? 'led-danger' : (sev === 'high' ? 'led-warning' : 'led-success')}"></span>${escapeHtml(inc.severity || 'INFO')}</span>`;
        const dt = inc.ts ? new Date(inc.ts * 1000).toLocaleString() : '—';
        const title = inc.title || inc.kind || 'Incidente di rete';
        const statusMap = {
            'new': '<span class="chip" style="background:rgba(250, 127, 170, 0.2); color:var(--danger); border-color:var(--danger);">Nuovo</span>',
            'acknowledged': '<span class="chip" style="background:rgba(255, 184, 77, 0.2); color:var(--warning); border-color:var(--warning);">In carico</span>',
            'resolved': '<span class="chip" style="background:rgba(87, 217, 135, 0.2); color:var(--success); border-color:var(--success);">Risolto</span>',
            'false_positive': '<span class="chip">Falso positivo</span>'
        };
        const stBadge = statusMap[inc.status] || `<span class="chip">${escapeHtml(inc.status || 'unknown')}</span>`;

        return `<tr>
            <td style="font-size:12px; color:var(--text-muted); white-space:nowrap;">${escapeHtml(dt)}</td>
            <td><strong style="color:var(--primary);">${escapeHtml(title)}</strong><div style="font-size:11px; color:var(--text-muted);">${escapeHtml(inc.kind || '')}</div></td>
            <td>${sevBadge}</td>
            <td><span class="badge">${escapeHtml(inc.tenant || 'Generale')}</span></td>
            <td><code>${escapeHtml(inc.device_ip || inc.entity_id || '—')}</code></td>
            <td>${stBadge}</td>
            <td>
                <div style="display:flex; gap:6px; align-items:center;">
                    <button class="btn btn-secondary btn-small" onclick="openIncidentDetail(${inc.id})" title="Dettaglio e Root-Cause"><i class="fa-solid fa-magnifying-glass-chart"></i> Analisi</button>
                    ${currentRole === 'admin' || currentRole === 'operator' ? `
                    <select onchange="changeIncidentStatus(${inc.id}, this.value)" style="padding:3px 6px; font-size:11px; border-radius:6px; background:var(--surface-2); border:1px solid var(--border); color:var(--text);">
                        <option value="" disabled selected>Stato...</option>
                        <option value="acknowledged">Prendi in carico</option>
                        <option value="resolved">Risolvi</option>
                        <option value="false_positive">Falso positivo</option>
                    </select>` : ''}
                </div>
            </td>
        </tr>`;
    }).join('');
}

async function changeIncidentStatus(id, newStatus) {
    if (!newStatus) return;
    try {
        const res = await apiFetch(`/api/incidents/${id}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus })
        });
        if (!res || !res.ok) {
            showToast('Impossibile aggiornare lo stato dell\'incidente', 'error');
            return;
        }
        showToast('Stato incidente aggiornato con successo', 'ok');
        loadIncidentsList();
    } catch (e) {
        showToast('Errore: ' + e.message, 'error');
    }
}

async function openIncidentDetail(id) {
    currentIncidentId = id;
    const modal = document.getElementById('incidentDetailModal');
    const content = document.getElementById('incidentDetailContent');
    if (!modal || !content) return;

    modal.style.display = 'flex';
    content.innerHTML = `<div style="text-align:center; padding:30px;"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><p style="margin-top:10px; color:var(--text-muted);">Caricamento dettagli incidente #${id}...</p></div>`;

    try {
        const res = await apiFetch(`/api/incidents/${id}`);
        if (!res || !res.ok) {
            content.innerHTML = `<div class="alert-box alert-danger">Impossibile trovare i dettagli dell'incidente #${id}.</div>`;
            return;
        }
        const inc = await res.json();
        renderIncidentDetailView(inc);
    } catch (e) {
        content.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(e.message)}</div>`;
    }
}

function renderIncidentDetailView(inc) {
    const content = document.getElementById('incidentDetailContent');
    if (!content) return;

    const when = inc.ts ? new Date(inc.ts * 1000).toLocaleString() : '—';
    const eventsList = (inc.events || []).map(ev => {
        const evTs = ev.ts ? new Date(ev.ts * 1000).toLocaleTimeString() : '';
        return `<div style="padding:8px 12px; background:var(--surface-2); border-radius:6px; margin-bottom:6px; border-left:3px solid var(--primary); font-size:12px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                <strong>${escapeHtml(ev.event_type || 'evento')}</strong>
                <span style="color:var(--text-muted); font-size:11px;">${escapeHtml(evTs)}</span>
            </div>
            <div>${escapeHtml(ev.message || JSON.stringify(ev.attrs || ''))}</div>
        </div>`;
    }).join('') || `<div style="color:var(--text-muted); font-size:12px;">Nessun micro-evento registrato.</div>`;

    content.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:16px; border-bottom:1px solid var(--border); padding-bottom:12px;">
            <div>
                <h3 style="margin:0 0 4px; font-size:18px; color:var(--text);">${escapeHtml(inc.title || inc.kind || 'Dettaglio Incidente')}</h3>
                <span style="font-size:12px; color:var(--text-muted);"><i class="fa-regular fa-clock"></i> Rilevato il ${escapeHtml(when)} | Tenant: <strong>${escapeHtml(inc.tenant || 'Generale')}</strong></span>
            </div>
            <span class="badge" style="font-size:13px; text-transform:uppercase;">${escapeHtml(inc.severity || 'INFO')}</span>
        </div>

        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:12px; margin-bottom:18px;">
            <div class="kpi" style="padding:10px 14px;">
                <h4 style="font-size:11px; margin-bottom:4px;">Dispositivo Target</h4>
                <code style="font-size:13px; color:var(--primary);">${escapeHtml(inc.device_ip || inc.entity_id || '—')}</code>
            </div>
            <div class="kpi" style="padding:10px 14px;">
                <h4 style="font-size:11px; margin-bottom:4px;">Stato</h4>
                <strong style="font-size:13px;">${escapeHtml(inc.status || 'new')}</strong>
            </div>
            <div class="kpi" style="padding:10px 14px;">
                <h4 style="font-size:11px; margin-bottom:4px;">Tipo Regola</h4>
                <span style="font-size:12px;">${escapeHtml(inc.kind || '—')}</span>
            </div>
        </div>

        ${inc.root_cause_hint ? `
        <div style="background:rgba(169, 159, 242, 0.1); border:1px solid var(--primary); border-radius:8px; padding:12px 14px; margin-bottom:18px;">
            <h4 style="margin:0 0 6px; color:var(--primary); font-size:13px;"><i class="fa-solid fa-lightbulb"></i> Ipotesi Causa Principale (Root-Cause)</h4>
            <p style="margin:0; font-size:13px; line-height:1.5;">${escapeHtml(inc.root_cause_hint)}</p>
        </div>` : ''}

        <div style="margin-bottom:18px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <h4 style="margin:0; font-size:14px;"><i class="fa-solid fa-wand-magic-sparkles" style="color:var(--primary);"></i> Spiegazione &amp; Analisi AI</h4>
                <button class="btn btn-secondary btn-small" onclick="explainIncidentWithAi(${inc.id})" id="btnExplainAi"><i class="fa-solid fa-robot"></i> Genera Spiegazione</button>
            </div>
            <div id="incidentAiExplanation" style="display:none; padding:12px; background:var(--surface); border:1px solid var(--border); border-radius:8px; font-size:13px; line-height:1.55; white-space:pre-wrap;"></div>
        </div>

        <div style="margin-bottom:12px;">
            <h4 style="margin:0 0 8px; font-size:14px;"><i class="fa-solid fa-timeline"></i> Sequenza Eventi Correlati</h4>
            <div style="max-height:220px; overflow-y:auto;">${eventsList}</div>
        </div>
    `;
}

async function explainIncidentWithAi(id) {
    const out = document.getElementById('incidentAiExplanation');
    const btn = document.getElementById('btnExplainAi');
    if (!out) return;
    out.style.display = 'block';
    out.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> L'assistente AI sta analizzando la topologia e i log correlati...`;
    if (btn) btn.disabled = true;

    try {
        const res = await apiFetch(`/api/incidents/${id}/explain`, { method: 'POST' });
        if (!res || !res.ok) {
            out.innerHTML = `<span style="color:var(--danger);">Analisi AI non disponibile per questo incidente o nessun profilo AI attivo configurato.</span>`;
            if (btn) btn.disabled = false;
            return;
        }
        const d = await res.json();
        out.innerHTML = escapeHtml(d.explanation || d.text || 'Nessuna analisi generata.');
    } catch (e) {
        out.innerHTML = `<span style="color:var(--danger);">${escapeHtml(e.message)}</span>`;
    } finally {
        if (btn) btn.disabled = false;
    }
}

function closeIncidentModal() {
    const modal = document.getElementById('incidentDetailModal');
    if (modal) modal.style.display = 'none';
}

// ===== Correlation Rules Catalog =====

async function loadCorrelationRules() {
    const box = document.getElementById('incRulesContainer');
    if (!box) return;
    box.innerHTML = `<div style="text-align:center; padding:30px;"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><p style="margin-top:10px; color:var(--text-muted);">Caricamento catalogo regole di correlazione...</p></div>`;

    try {
        const res = await apiFetch('/api/incidents/rules');
        if (!res || !res.ok) {
            box.innerHTML = `<div class="alert-box alert-danger">Impossibile caricare le regole di correlazione.</div>`;
            return;
        }
        const data = await res.json();
        renderCorrelationRulesList(data.rules || []);
    } catch (e) {
        box.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(e.message)}</div>`;
    }
}

function renderCorrelationRulesList(rulesList) {
    const box = document.getElementById('incRulesContainer');
    if (!box) return;
    if (rulesList.length === 0) {
        box.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-muted);">Nessuna regola definita.</div>`;
        return;
    }

    box.innerHTML = rulesList.map(r => {
        const paramsList = (r.parameters || []).map(p => {
            const curVal = (r.effective_params && r.effective_params[p.name] !== undefined) ? r.effective_params[p.name] : p.default;
            return `<div style="display:flex; align-items:center; justify-content:space-between; gap:12px; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.05);">
                <div>
                    <strong style="font-size:12px;">${escapeHtml(p.name)}</strong>
                    <div style="font-size:11px; color:var(--text-muted);">${escapeHtml(p.description || '')} (${p.min} - ${p.max})</div>
                </div>
                <input type="number" id="rule_param_${escapeHtml(r.id)}_${escapeHtml(p.name)}" value="${curVal}" min="${p.min}" max="${p.max}" step="1"
                       style="width:90px; padding:4px 8px; font-size:12px; border-radius:6px; background:var(--surface); border:1px solid var(--border); color:var(--text); text-align:right;">
            </div>`;
        }).join('');

        return `<div class="panel" style="margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
                <div>
                    <h4 style="margin:0 0 4px; font-size:15px; color:var(--primary);">${escapeHtml(r.name || r.id)}</h4>
                    <p style="margin:0; font-size:13px; color:var(--text-muted);">${escapeHtml(r.description || '')}</p>
                </div>
                <span class="chip">${escapeHtml(r.category || 'anomaly')}</span>
            </div>
            ${paramsList ? `
            <div style="background:var(--surface-2); border-radius:8px; padding:10px 14px; margin:12px 0;">
                <h5 style="margin:0 0 8px; font-size:12px; text-transform:uppercase; color:var(--text-muted);">Parametri e Soglie</h5>
                ${paramsList}
            </div>` : ''}
            ${currentRole === 'admin' && paramsList ? `
            <div style="display:flex; justify-content:flex-end;">
                <button class="btn btn-primary btn-small" onclick="saveRuleParameters('${escapeHtml(r.id)}', ${JSON.stringify(r.parameters || []).replace(/"/g, '&quot;')})">
                    <i class="fa-solid fa-floppy-disk"></i> Salva Soglie
                </button>
            </div>` : ''}
        </div>`;
    }).join('');
}

async function saveRuleParameters(ruleId, paramsMeta) {
    const payload = {};
    for (const p of paramsMeta) {
        const inp = document.getElementById(`rule_param_${ruleId}_${p.name}`);
        if (inp) {
            const val = parseFloat(inp.value);
            if (isNaN(val) || val < p.min || val > p.max) {
                showToast(`Parametro '${p.name}' non valido (deve essere tra ${p.min} e ${p.max})`, 'warning');
                return;
            }
            payload[p.name] = val;
        }
    }

    try {
        const res = await apiFetch(`/api/incidents/rules/${encodeURIComponent(ruleId)}/parameters`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!res || !res.ok) {
            showToast('Errore durante il salvataggio dei parametri della regola', 'error');
            return;
        }
        showToast('Soglie regola aggiornate con successo!', 'ok');
        loadCorrelationRules();
    } catch (e) {
        showToast('Errore: ' + e.message, 'error');
    }
}

// ===== Interface Flapping & Suppression Windows =====

async function loadInterfaceSuppressions() {
    const tbody = document.getElementById('incSuppressionTableBody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="6" style="padding:20px; text-align:center; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin"></i> Caricamento stati interfacce...</td></tr>`;

    try {
        const res = await apiFetch('/api/incidents/interfaces');
        if (!res || !res.ok) {
            tbody.innerHTML = `<tr><td colspan="6" style="padding:16px; text-align:center; color:var(--danger);">Impossibile caricare le interfacce.</td></tr>`;
            return;
        }
        const data = await res.json();
        const items = data.interfaces || [];
        renderSuppressionsTable(items);
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" style="padding:16px; text-align:center; color:var(--danger);">${escapeHtml(e.message)}</td></tr>`;
    }
}

function renderSuppressionsTable(items) {
    const tbody = document.getElementById('incSuppressionTableBody');
    if (!tbody) return;
    if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="padding:20px; text-align:center; color:var(--text-muted);">Nessuna interfaccia monitorata registrata negli eventi recenti.</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(item => {
        const isSupp = item.suppressed;
        const suppBadge = isSupp ? '<span class="status warn"><span class="led led-warning"></span>Soppressa</span>' : '<span class="status ok"><span class="led led-success"></span>Attiva</span>';
        const note = item.note ? `<div style="font-size:11px; color:var(--text-muted);">${escapeHtml(item.note)}</div>` : '';

        return `<tr>
            <td><strong>${escapeHtml(item.hostname || item.device_ip)}</strong></td>
            <td><code>${escapeHtml(item.device_ip)}</code></td>
            <td><code style="color:var(--primary);">${escapeHtml(item.interface)}</code></td>
            <td><span class="badge">${escapeHtml(item.tenant || 'Generale')}</span></td>
            <td>${suppBadge}${note}</td>
            <td>
                ${currentRole === 'admin' || currentRole === 'operator' ? `
                <button class="btn btn-secondary btn-small" onclick="toggleInterfaceSuppression('${escapeHtml(item.tenant)}', '${escapeHtml(item.device_ip)}', '${escapeHtml(item.interface)}', ${!isSupp})">
                    <i class="fa-solid ${isSupp ? 'fa-eye' : 'fa-eye-slash'}"></i> ${isSupp ? 'Ripristina' : 'Sopprimi'}
                </button>` : '—'}
            </td>
        </tr>`;
    }).join('');
}

async function toggleInterfaceSuppression(tenant, deviceIp, iface, suppress) {
    let note = '';
    if (suppress) {
        note = prompt('Inserisci un motivo per la finestra di soppressione/manutenzione:', 'Manutenzione programmata');
        if (note === null) return;
    }

    try {
        const res = await apiFetch('/api/incidents/interfaces/expected', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tenant: tenant,
                device_ip: deviceIp,
                interface: iface,
                suppressed: suppress,
                note: note
            })
        });
        if (!res || !res.ok) {
            showToast('Impossibile aggiornare la soppressione interfaccia', 'error');
            return;
        }
        showToast(`Interfaccia ${iface} ${suppress ? 'soppressa' : 'riattivata'} con successo.`, 'ok');
        loadInterfaceSuppressions();
    } catch (e) {
        showToast('Errore: ' + e.message, 'error');
    }
}
