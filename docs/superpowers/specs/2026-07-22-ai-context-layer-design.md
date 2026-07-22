# Design — AI context layer (unit 2c-1)

Porta i sei *context builder* di `routers/ai.py` che alimentano `/api/ai/chat`
e `/api/ai/generate-config`, più le funzioni di supporto (query obsstore, mac
stats scoped). **Fuori scope**: i due endpoint HTTP e l'orchestrazione (unità
2c-2). Questo spec produce funzioni di raccolta contesto testabili in
isolamento.

## Obiettivo

Fornire, come metodi su `*App`, i blocchi di contesto testuale che l'AI
Assistant allega alle richieste, con lo scoping per tenant/utente identico al
Python, più le due aggiunte di storage che i builder richiedono.

## Architettura

- Nuovo file `internal/api/ai_context.go`: i sei builder come metodi su `*App`.
- Aggiunta `internal/store/mac.go`: `MacStatsScoped(tenants []string)`.
- Aggiunta `internal/obsstore/queries.go`: `TopFlowsContext(...)`.
- Micro-refactor `internal/api/fortigate_handlers.go`: estrarre
  `fgtDeviceByIP(w, r, ip)` da `fgtDevice` (che oggi legge l'IP dalla rotta),
  così un builder può risolvere un FortiGate da un IP del payload.
- Accessor `internal/observability/manager.go`: `FlowRetentionDays() int`.

## Contratto d'errore (interfaccia verso 2c-2)

Si segue la convenzione già in uso nel package (`assertDeviceAllowed`,
`fgtDevice`, `fgtRespond`): i builder che possono fallire prendono `(w, r, …)`
e ritornano `(string, bool)` — in caso di errore scrivono già la risposta HTTP
con lo status corretto su `w` e ritornano `ok=false`; il chiamante (endpoint
2c-2) fa `return` immediato. I builder che non falliscono mai ritornano una
semplice `string`. Nessun nuovo tipo d'errore: gli status code viaggiano
attraverso `writeErr`, come nel resto del package.

## I sei builder

### 1. deviceInventorySummary(scoped []string) string
Puro. Riepilogo testuale dell'inventario, filtrato con `canSeeTenant(scoped,
d.Tenant)` (scoped `nil` = admin, nessun filtro). Cap 200 dispositivi + riga
"... e altri N (troncato)". Testo 1:1 con `_device_inventory_summary`:
`- {IP} | {Hostname|(senza hostname)} | vendor={Vendor} | sede={Tenant}`.

### 2. deviceRunningConfigContext(w, r, ip) (string, bool)
`assertDeviceAllowed(w, r, ip)` (scrive 404/403, `ok=false`), poi
`configanalyzer.LoadBackupRunningConfig(a.cfg.BackupDir(), ip)`; se `!ok` →
`writeErr(404, "Nessun backup trovato per {ip}.")`. Ritorna
`"Running-config di {ip}:\n\n{running-config}"`, true.

Divergenza (→ §15): il Python distingue 404 "nessun backup" da 500 "file
illeggibile"; `LoadBackupRunningConfig` collassa entrambi in un bool, quindi il
file illeggibile diventa 404. Il caso è di fatto irraggiungibile (il file è
appena stato trovato da `FindFreshestBackup`).

### 3. fortigateLiveContext(w, r, ip) (string, bool)
Risolve il device con `fgtDeviceByIP(w, r, ip)` (scoping tenant + verifica
vendor FortiGate + costruzione client; in caso negativo scrive la risposta e
`ok=false`). Poi, best-effort:
- `SystemStatus`: `## FortiGate {ip} — dati live` + `Stato sistema (fonte
  {source}):\n{json}` troncato a 4000 char; se errore → `Stato sistema non
  disponibile: {err}`.
- `FullConfig`: `Configurazione completa (fonte {source}):\n{text}`; se
  `len>120000` tronca con `\n... [config troncata]`; se errore → `Configurazione
  live non disponibile: {err}`.

Ritorna il blocco (join `\n\n`), true. Gli errori di fetch sono testo nel
blocco, non falliscono la richiesta — come il Python.

### 4. tenantContextBlock(w, r, tenant) (string, bool)
Scoping di gruppo: se `tenant` non è tra i gruppi noti dell'inventario → 404
"Sede/tenant '{tenant}' non trovata."; se `!canSeeTenant(scoped, tenant)` → 403.
Raccoglie, tutto filtrato per quel tenant:
- devices con `d.Tenant == tenant`;
- group info (metadati del gruppo, se disponibili);
- sedi VPN: `site_ids = {d.Site|"central"}` → `store.GetSite(id)` per ognuna;
- `MacStatsScoped([]string{tenant})` + `retention_days` da
  `obsMgr.FlowRetentionDays()` (se `obsMgr == nil` → chiave assente, il
  formatter mostra "?");
- `SearchSightings(tenants=[tenant], limit=15)` come mac recent.

Mappa in `ai.TenantContextArgs` e ritorna `ai.BuildTenantContext(args)`, true.
Le mappe passate al formatter usano le stesse chiavi che `BuildTenantContext`
già legge (`sightings`, `unique_macs`, `switches`, `retention_days`; per i
recent `mac`, `switch_ip`, ...).

### 5. tenantCommonParameters(w, r, tenant) (string, bool)
Solo per generate-config. Stesso scoping di gruppo del builder 4. Distilla i
parametri comuni dell'ambiente dai backup dei dispositivi del tenant:
- per ogni device con backup (`LoadBackupRunningConfig`), cap 15 analizzati;
- conta le righe globali (non indentate) che iniziano con i prefissi comuni
  (`_COMMON_GLOBAL_PREFIXES`: vtp, ntp, logging, snmp-server, aaa, ip domain,
  ip name-server, ip default-gateway, clock timezone, clock summer-time,
  spanning-tree, ip ssh, service, radius, tacacs);
- raccoglie VLAN (`vlan <id>` + eventuale `name`) e subnet di management
  (`interface vlan N` → `ip address A M`);
- soglia "comune" = `max(1, (analyzed+1)/2)`.
Se `analyzed == 0` → 404 "Nessun backup di configurazione disponibile per il
tenant '{tenant}'.". Testo 1:1 con `_tenant_common_parameters` (header, "VLAN in
uso", "Subnet di management osservate", "Comandi globali comuni", cap 120 righe).

### 6. topFlowsContext(scoped []string, keys []obsstore.FlowKey) string
Puro. Blocco markdown dei top flussi (finestra 900s, limit 20), scoped per
tenant, con opzionale vincolo per-tupla `keys`. Usa la nuova
`obsstore.TopFlowsContext`. Il tipo `obsstore.FlowKey{SrcIP, DstIP string;
Protocol int; DstPort *int}` è definito in obsstore (lo consuma la query; il
builder e l'endpoint 2c-2 lo importano — evita il ciclo api→obsstore→api).
Formato 1:1 con `top_flows_context`:
- header `## Top flussi di rete (ultimi {window/60} minuti, {N} aggregati)`;
- `(nessun flusso registrato nella finestra)` se vuoto;
- righe `- [{tenant}] {src} → {dst} {PROTO}/{dport|-}: {bytes} byte, {packets}
  pacchetti` (proto map 6→TCP, 17→UDP, 1→ICMP, altro→numero);
- se anomalie: `## Anomalie correlate aperte (ultime 24h)` +
  `- [{tenant}] {kind} sev={severity}: {src} → {dst}{ — porta {port} se
  presente}`.
Se `obsMgr`/`obs` non collegati, ritorna un blocco vuoto (nessun flusso) —
mai panic.

## Aggiunte di supporto

### store.MacStatsScoped(tenants []string) (sightings, uniqueMacs, switches int, err error)
Come `MacStats()` ma con `WHERE tenant IN (...)` quando `tenants != nil`.
`tenants` vuoto (non nil) → tutti zero (nessun tenant visibile), come Python.
Divergenza (→ §15): il contesto tenant ora usa conteggi mac scoped per tenant;
`MacStats()` globale resta per gli altri chiamanti.

### obsstore.TopFlowsContext(cutoff int64, scope []string, keys []obsstore.FlowKey, limit int) ([]TopFlow, []Anomaly, error)
`FlowKey{SrcIP, DstIP string; Protocol int; DstPort *int}` è definita in questo
package (obsstore).
- Flussi: `SELECT tenant, src_ip, dst_ip, protocol, dst_port, SUM(total_bytes),
  SUM(total_packets) FROM flow_aggregates WHERE window_start >= ?` + il filtro
  scope (riusa `tenantClause(scope)`) + il filtro `keys` opzionale (OR di tuple
  `(src_ip=? AND dst_ip=? AND protocol=? AND dst_port=?|IS NULL)`), `GROUP BY`
  le 5 colonne, `ORDER BY SUM(total_bytes) DESC LIMIT ?`. Riempie `[]TopFlow`
  (struct già esistente, `DstPort *int`).
- Anomalie: `correlated_events` con `status != 'resolved' AND created_ts >=
  (now-86400)` + scope, `ORDER BY created_ts DESC LIMIT 10`. Struct `Anomaly`
  minimale con `Tenant, Kind, SrcIP, DstIP, SwitchPort string; Severity`.
Lo scope tenant è sempre in AND: i `keys` forniti dal client non possono
estrarre righe di altri tenant.

### observability.Manager.FlowRetentionDays() int
Ritorna `m.config.RetentionDays.daysFor("flow_aggregates")` (o l'equivalente
accessibile). Usato solo per popolare `retention_days` nel contesto tenant.

### api.fgtDeviceByIP(w, r, ip) (*store.Device, *fortigate.Client, bool)
Estratto da `fgtDevice`: stessa logica (assertDeviceAllowed → vendor FortiGate →
`fgtClient`) ma con `ip` esplicito. `fgtDevice` diventa
`return a.fgtDeviceByIP(w, r, chi.URLParam(r, "ip"))`.

## Divergenze dal Python (→ DIVERGENZE-DAL-PYTHON.md §15)

1. `deviceRunningConfigContext`: file di backup illeggibile → 404 invece di 500
   (collassato da `LoadBackupRunningConfig`). Caso di fatto irraggiungibile.
2. `tenantContextBlock`: le mac stats del contesto sono ora scoped per tenant
   (`MacStatsScoped`); `MacStats()` globale invariato per gli altri usi.

## Test

- `internal/api/ai_context_test.go` (store + obsstore in-memory, `httptest`
  recorder + request con claims, come gli altri handler test):
  - inventory: scoping per tenant + cap 200/troncamento;
  - running-config: 404 su backup mancante, 403 fuori scope, testo su backup
    presente;
  - fortigate live: contro un fake FortiGate httptest (pattern
    `fortigate_handlers_test.go`) — blocco con status+config; device non
    FortiGate → 400; fuori scope → 403;
  - tenant block: 404 gruppo sconosciuto, 403 fuori scope, testo assemblato via
    `BuildTenantContext` con mac stats scoped e sedi;
  - tenant common params: distillazione soglia-metà + 404 senza backup;
  - top flows: header/righe/anomalie con righe seminate; proto map; `keys`
    che vincola le tuple; scope che esclude altri tenant.
- `internal/store/mac_test.go`: `MacStatsScoped` filtra per tenant; `tenants`
  vuoto → zero.
- `internal/obsstore/queries_test.go`: `TopFlowsContext` — grouping, scope,
  vincolo `keys` (incl. `dst_port IS NULL`), anomalie non-resolved.

## Fuori scope (unità 2c-2)

`/api/ai/chat` (8 flag di allegato, budget/`FitContext`, blocco istruzioni di
proposta config, lookup profilo attivo, mapping errori) e
`/api/ai/generate-config`. Consumeranno i builder di questo spec.
