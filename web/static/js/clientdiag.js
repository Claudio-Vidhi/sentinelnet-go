// ===== Unified Client 360 & Diagnostics =====

async function openClientDiagModal(clientIpOrMac) {
    const modal = document.getElementById('clientDiagModal');
    if (!modal) return;
    modal.style.display = 'flex';

    const targetInput = document.getElementById('diagClientTarget');
    if (targetInput && clientIpOrMac) {
        targetInput.value = clientIpOrMac;
    }
    document.getElementById('diagResultsContainer').innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);"><i class="fa-solid fa-stethoscope fa-2x" style="color:var(--primary); margin-bottom:10px;"></i><p>Inserisci un IP o MAC e avvia l'analisi end-to-end.</p></div>`;
}

function closeClientDiagModal() {
    const modal = document.getElementById('clientDiagModal');
    if (modal) modal.style.display = 'none';
}

async function runClient360Diagnosis() {
    const clientVal = document.getElementById('diagClientTarget') ? document.getElementById('diagClientTarget').value.trim() : '';
    const destVal = document.getElementById('diagDestTarget') ? document.getElementById('diagDestTarget').value.trim() : '';
    const box = document.getElementById('diagResultsContainer');
    const btn = document.getElementById('btnRunClientDiag');

    if (!clientVal) {
        showToast('Inserisci un indirizzo IP o MAC del client', 'warning');
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Diagnosi in corso...`;
    }
    if (box) {
        box.innerHTML = `<div style="text-align:center; padding:30px;"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><p style="margin-top:10px; color:var(--text-muted);">Tracciamento client nella topologia, binding ARP, VLAN, switch port e gateway...</p></div>`;
    }

    try {
        const res = await apiFetch('/api/diagnose/client', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client: clientVal, dest: destVal })
        });

        if (!res || !res.ok) {
            const err = await res.json();
            if (box) box.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(err.detail || 'Errore durante la diagnosi del client')}</div>`;
            return;
        }

        const data = await res.json();
        renderClientDiagResults(data);
    } catch (e) {
        if (box) box.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(e.message)}</div>`;
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-play"></i> Avvia Diagnosi 360°`;
        }
    }
}

function renderClientDiagResults(rep) {
    const box = document.getElementById('diagResultsContainer');
    if (!box) return;

    const sections = [
        { key: 'arp', title: 'Risoluzione ARP & Binding IP', icon: 'fa-network-wired' },
        { key: 'mac', title: 'Posizione Fisica (Switch / Porta)', icon: 'fa-location-dot' },
        { key: 'gateway', title: 'Default Gateway & Routing', icon: 'fa-route' },
        { key: 'dhcp', title: 'Stato DHCP & Lease', icon: 'fa-server' },
        { key: 'fortigate', title: 'Firewall FortiGate & Policy', icon: 'fa-shield-halved' },
        { key: 'wlc', title: 'Wireless WLC / AP / Radio', icon: 'fa-wifi' }
    ];

    const hopsHtml = sections.map(s => {
        const d = rep[s.key];
        if (!d) return '';
        const status = d.status || (d.found !== false ? 'ok' : 'warn');
        const stBadge = status === 'ok' ?
            `<span class="status ok"><span class="led led-success"></span>OK</span>` :
            `<span class="status warn"><span class="led led-warning"></span>ATTENZIONE</span>`;

        return `
            <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:12px; margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <i class="fa-solid ${s.icon}" style="color:var(--primary);"></i>
                        <strong style="font-size:13px;">${s.title}</strong>
                    </div>
                    ${stBadge}
                </div>
                <div style="font-size:12px; color:var(--text); line-height:1.45;">
                    ${renderDiagSectionBody(s.key, d)}
                </div>
            </div>
        `;
    }).join('');

    const switchIp = rep.mac ? rep.mac.switch_ip : (rep.switch_ip || '');
    const iface = rep.mac ? rep.mac.interface : (rep.interface || '');
    const clientMac = rep.mac ? rep.mac.mac : (rep.client_mac || '');

    const remediationHtml = (switchIp && iface) ? `
        <div class="panel requires-write" style="margin-top:16px; background:rgba(169, 159, 242, 0.05); border:1px solid var(--primary);">
            <h4 style="margin:0 0 8px; font-size:13px; color:var(--primary);"><i class="fa-solid fa-bolt"></i> Azioni Rapide di Remediation</h4>
            <p style="margin:0 0 10px; font-size:12px; color:var(--text-muted);">
                Apparato di accesso: <strong>${escapeHtml(switchIp)}</strong> sulla porta <strong>${escapeHtml(iface)}</strong>.
            </p>
            <div style="display:flex; gap:10px;">
                <button class="btn btn-secondary btn-small" onclick="executePortBounce('${escapeHtml(switchIp)}', '${escapeHtml(iface)}', '${escapeHtml(clientMac)}')" style="color:var(--warning); border-color:var(--warning);">
                    <i class="fa-solid fa-arrows-rotate"></i> Port Bounce (Shut/No-Shut)
                </button>
                <button class="btn btn-secondary btn-small" onclick="toggleInterfaceAdminState('${escapeHtml(switchIp)}', '${escapeHtml(iface)}', false)" style="color:var(--danger); border-color:var(--danger);">
                    <i class="fa-solid fa-power-off"></i> Disabilita Porta
                </button>
            </div>
        </div>
    ` : '';

    box.innerHTML = `
        <div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
                <h4 style="margin:0; font-size:15px; color:var(--text);"><i class="fa-solid fa-check-double" style="color:var(--success);"></i> Diagnosi End-to-End Completata</h4>
                <span style="font-size:12px; color:var(--text-muted);">Target: <code>${escapeHtml(rep.client || '')}</code></span>
            </div>
            ${hopsHtml || '<div style="color:var(--text-muted); padding:16px;">Nessun dato raccolto.</div>'}
            ${remediationHtml}
        </div>
    `;
}

function renderDiagSectionBody(key, data) {
    if (key === 'mac') {
        return `Switch: <strong>${escapeHtml(data.switch_ip || data.switch || '—')}</strong> | Porta: <code style="color:var(--primary);">${escapeHtml(data.interface || '—')}</code> | VLAN: <strong>${escapeHtml(data.vlan || '—')}</strong>`;
    }
    if (key === 'arp') {
        return `IP: <code>${escapeHtml(data.ip || '—')}</code> &harr; MAC: <code>${escapeHtml(data.mac || '—')}</code> | Sorgente ARP: <strong>${escapeHtml(data.source_ip || '—')}</strong>`;
    }
    if (key === 'gateway') {
        return `Default Gateway: <code>${escapeHtml(data.gateway_ip || data.gateway || '—')}</code> | Ping: <strong>${data.ping_ok ? '<span style="color:var(--success);">Raggiungibile</span>' : '<span style="color:var(--danger);">Non raggiungibile</span>'}</strong>`;
    }
    return escapeHtml(JSON.stringify(data));
}

// ===== Port Remediation Workflows =====

async function executePortBounce(switchIp, iface, clientMac) {
    if (!confirm(`Confermi il PORT BOUNCE (shutdown immediato e no-shutdown) sulla porta ${iface} dello switch ${switchIp}?`)) return;

    try {
        const res = await apiFetch('/api/diagnose/port-bounce', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                switch_ip: switchIp,
                interface: iface,
                client_mac: clientMac
            })
        });

        if (!res || !res.ok) {
            const err = await res.json();
            showToast(`Port bounce rifiutato o fallito: ${err.detail || 'Errore'}`, 'error');
            return;
        }
        showToast(`Port bounce eseguito con successo su ${switchIp} (${iface})!`, 'ok');
    } catch (e) {
        showToast('Errore: ' + e.message, 'error');
    }
}

async function toggleInterfaceAdminState(switchIp, iface, adminUp) {
    const actionName = adminUp ? 'abilitare' : 'DISABILITARE';
    if (!confirm(`Sei sicuro di voler ${actionName} la porta ${iface} sullo switch ${switchIp}?`)) return;

    try {
        const res = await apiFetch('/api/interfaces/state', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                switch_ip: switchIp,
                interface: iface,
                admin_up: adminUp
            })
        });

        if (!res || !res.ok) {
            const err = await res.json();
            showToast(`Operazione fallita: ${err.detail || 'Errore'}`, 'error');
            return;
        }
        showToast(`Stato porta ${iface} impostato a ${adminUp ? 'UP' : 'DOWN'} con successo!`, 'ok');
    } catch (e) {
        showToast('Errore: ' + e.message, 'error');
    }
}
