// ===== High Availability & Redundancy Groups =====

async function loadRedundancyTab() {
    const container = document.getElementById('redundancyGroupsContainer');
    if (!container) return;
    container.innerHTML = `<div style="text-align:center; padding:30px;"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><p style="margin-top:10px; color:var(--text-muted);">Caricamento gruppi di ridondanza e HA...</p></div>`;

    try {
        const res = await apiFetch('/api/redundancy/groups');
        if (!res || !res.ok) {
            container.innerHTML = `<div class="alert-box alert-danger">Impossibile caricare i gruppi di ridondanza.</div>`;
            return;
        }
        const data = await res.json();
        const groups = data.results || [];
        renderRedundancyGroups(groups);
        updateRedundancyKpis(groups);
    } catch (e) {
        container.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(e.message)}</div>`;
    }
}

function updateRedundancyKpis(groups) {
    let healthy = 0, degraded = 0, critical = 0;
    groups.forEach(g => {
        const h = (g.health || '').toLowerCase();
        if (h === 'healthy' || h === 'ok') healthy++;
        else if (h === 'degraded' || h === 'warning') degraded++;
        else critical++;
    });
    const setText = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    setText('haKpiTotal', groups.length);
    setText('haKpiHealthy', healthy);
    setText('haKpiDegraded', degraded);
    setText('haKpiCritical', critical);
}

function renderRedundancyGroups(groups) {
    const container = document.getElementById('redundancyGroupsContainer');
    if (!container) return;

    if (groups.length === 0) {
        container.innerHTML = `
            <div class="panel" style="text-align:center; padding:40px;">
                <i class="fa-solid fa-layer-group" style="font-size:36px; color:var(--text-muted); margin-bottom:12px;"></i>
                <h3 style="margin-bottom:8px;">Nessun gruppo di ridondanza registrato</h3>
                <p style="color:var(--text-muted); font-size:13px; max-width:500px; margin:0 auto 16px;">
                    Crea un gruppo per monitorare cluster HSRP, VRRP, FortiGate HA, Cisco StackWise o coppie VPC/MLAG.
                </p>
                ${currentRole === 'admin' ? `
                <button class="btn btn-primary" onclick="openCreateRedundancyModal()" style="width:auto; margin:0 auto;">
                    <i class="fa-solid fa-plus"></i> Crea Gruppo HA
                </button>` : ''}
            </div>
        `;
        return;
    }

    container.innerHTML = `
        <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(340px, 1fr)); gap:18px;">
            ${groups.map(g => renderRedundancyCard(g)).join('')}
        </div>
    `;
}

function renderRedundancyCard(g) {
    const health = (g.health || 'unknown').toLowerCase();
    const isHealthy = health === 'healthy' || health === 'ok';
    const isDegraded = health === 'degraded' || health === 'warning';
    const healthBadge = isHealthy ?
        `<span class="status ok"><span class="led led-success"></span>HEALTHY</span>` :
        (isDegraded ? `<span class="status warn"><span class="led led-warning"></span>DEGRADED</span>` : `<span class="status bad"><span class="led led-danger"></span>CRITICAL</span>`);

    const members = (g.members || []).map(m => {
        const isMaster = (m.role || '').toLowerCase().includes('master') || (m.role || '').toLowerCase().includes('active') || (m.state || '').toLowerCase().includes('active');
        const roleIcon = isMaster ? '<i class="fa-solid fa-crown" style="color:var(--warning); margin-right:4px;"></i>' : '<i class="fa-solid fa-shield" style="color:var(--text-muted); margin-right:4px;"></i>';

        return `<div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.05); font-size:12px;">
            <div>
                ${roleIcon}<strong>${escapeHtml(m.device_ip)}</strong>
                ${m.interface ? `<span style="color:var(--text-muted); font-size:11px; margin-left:4px;">(${escapeHtml(m.interface)})</span>` : ''}
            </div>
            <div style="display:flex; gap:6px; align-items:center;">
                <span class="chip" style="font-size:10px;">${escapeHtml(m.role || m.state || 'member')}</span>
                ${m.priority !== undefined ? `<span style="font-size:11px; color:var(--text-muted);">Prio: ${m.priority}</span>` : ''}
            </div>
        </div>`;
    }).join('') || `<div style="color:var(--text-muted); font-size:12px; padding:6px 0;">Nessun membro associato.</div>`;

    return `
        <div class="panel" style="display:flex; flex-direction:column; justify-content:space-between;">
            <div>
                <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
                    <div>
                        <h4 style="margin:0 0 4px; font-size:16px; color:var(--text);">${escapeHtml(g.name || g.group_name || 'Gruppo HA')}</h4>
                        <span style="font-size:12px; color:var(--text-muted);">${escapeHtml(g.protocol || 'VRRP/HSRP')} | Tenant: <strong>${escapeHtml(g.group_name || 'Generale')}</strong></span>
                    </div>
                    ${healthBadge}
                </div>

                ${g.virtual_ip ? `
                <div style="background:var(--surface-2); border-radius:6px; padding:6px 10px; margin-bottom:12px; font-size:12px;">
                    <span style="color:var(--text-muted);">VIP:</span> <code style="color:var(--primary); font-weight:700;">${escapeHtml(g.virtual_ip)}</code>
                </div>` : ''}

                <div style="margin-bottom:14px;">
                    <h5 style="margin:0 0 6px; font-size:11px; text-transform:uppercase; color:var(--text-muted);">Membri del Cluster</h5>
                    ${members}
                </div>
            </div>

            <div style="display:flex; justify-content:flex-end; gap:8px; border-top:1px solid var(--border); padding-top:10px; margin-top:8px;">
                ${currentRole === 'admin' ? `
                <button class="btn btn-secondary btn-small" onclick="deleteRedundancyGroup(${g.id})" style="color:var(--danger); width:auto;" title="Elimina gruppo">
                    <i class="fa-solid fa-trash"></i>
                </button>` : ''}
            </div>
        </div>
    `;
}

function openCreateRedundancyModal() {
    const modal = document.getElementById('createRedundancyModal');
    if (modal) modal.style.display = 'flex';
}

function closeCreateRedundancyModal() {
    const modal = document.getElementById('createRedundancyModal');
    if (modal) modal.style.display = 'none';
}

async function submitCreateRedundancyGroup() {
    const name = document.getElementById('haGroupName') ? document.getElementById('haGroupName').value.trim() : '';
    const protocol = document.getElementById('haProtocol') ? document.getElementById('haProtocol').value : 'HSRP';
    const vip = document.getElementById('haVirtualIp') ? document.getElementById('haVirtualIp').value.trim() : '';
    const tenant = document.getElementById('haTenant') ? document.getElementById('haTenant').value : 'default';

    if (!name) {
        showToast('Inserisci un nome per il gruppo di ridondanza', 'warning');
        return;
    }

    try {
        const res = await apiFetch('/api/redundancy/groups', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: name,
                group_name: tenant,
                protocol: protocol,
                virtual_ip: vip,
                detection_source: 'manual',
                members: []
            })
        });
        if (!res || !res.ok) {
            showToast('Errore durante la creazione del gruppo HA', 'error');
            return;
        }
        showToast('Gruppo HA creato con successo!', 'ok');
        closeCreateRedundancyModal();
        loadRedundancyTab();
    } catch (e) {
        showToast('Errore: ' + e.message, 'error');
    }
}

async function deleteRedundancyGroup(id) {
    if (!confirm(`Sei sicuro di voler eliminare il gruppo di ridondanza #${id}?`)) return;

    try {
        const res = await apiFetch(`/api/redundancy/groups/${id}`, { method: 'DELETE' });
        if (!res || !res.ok) {
            showToast('Impossibile eliminare il gruppo HA', 'error');
            return;
        }
        showToast('Gruppo HA eliminato con successo.', 'ok');
        loadRedundancyTab();
    } catch (e) {
        showToast('Errore: ' + e.message, 'error');
    }
}
