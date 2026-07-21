# SentinelNet → Go: Porting Plan (continuation)

Stato: **il port è circa a metà.** Questo documento copre la metà restante.

- **Sorgente**: `../SentinelNet` (Python 3 / FastAPI, 84 file `.py`)
- **Target**: questo repo — `github.com/Claudio-Vidhi/sentinelnet-go`, Go 1.26
- **Stack già scelto**: `go-chi/chi/v5`, `modernc.org/sqlite` (puro-Go, no CGO), `coder/websocket`,
  `golang-jwt/v5`, `golang.org/x/crypto`, `golang.org/x/sync`
- Sostituisce il `GO_PORT_PLAN.md` rimosso nel commit `2f44d6e`.

---

## 1. Vincoli invarianti (non negoziabili)

1. **`web/dashboard.html` è servito invariato.** Ogni contratto JSON sotto `/api/...` deve restare
   compatibile campo-per-campo. Nessun rename, nessun cambio di forma, nessun "miglioramento".
2. **Binario unico statico, nessun CGO.** Niente dipendenze che richiedano toolchain C.
3. **Porta 1:1, non riprogettare.** Dove il Python ha un limite noto (es. nessun rollback nel
   provisioning), il port lo *preserva e lo documenta* — non lo "aggiusta" silenziosamente.
   Le eccezioni deliberate sono elencate in §7.
4. **Dipendenze: aggiungerne il minimo.** Vedi §6 — l'intero piano richiede **una sola** nuova dipendenza.

---

## 2. Stato attuale

### Già portato
`internal/store` (SQLite WAL + migrazioni embed), `internal/auth` (JWT HS256, bcrypt, lockout),
`internal/crypto` (vault AES-GCM), `internal/collect` (SSH/CLI Netmiko-lite, triage, backup, ping,
terminale WS), `internal/topology` (CDP/LLDP, port-channel, VTP), `internal/mac` (parser CLI),
`internal/configanalyzer` (running-config Cisco), `internal/euvd` (proxy ENISA), `internal/ui`,
`internal/api` (~60 rotte).

Coperti a livello di rotta: auth, users, inventory, catalog (groups/vendors/models/categories),
topology core, commands, triage, scan, mac, config-analyzer (GET), backup, euvd, settings/network.

### Da portare (perimetro di questo piano)

| Dominio | Moduli Python | Rotte | Copertura Go |
|---|---|---|---|
| **A — Observability** | `observability/*` (14 file) + `core/db.py` | 10 | **nessuna** |
| **B — Driver / Collector / FW-analyzer** | `drivers/*` (9), `collectors/*` (4), `fw_analyzers/*` (3) | 5 | parziale |
| **C — Services** | `services/*` (8) | ~45 | **nessuna** |
| **D — AI / MCP / Security** | `ai/*` (4), `security/*` (5 residui) | 18 | parziale |

---

## 3. Difetti già presenti nel port Go (da correggere per primi)

Emersi dall'analisi; sono regressioni rispetto al Python, non semplici lacune.

> **Stato al 2026-07-20**: **tutti i difetti D1-D5 sono corretti** (vedi §14). D5 chiuso in 827d1e1.

| # | Difetto | Dove | Impatto |
|---|---|---|---|
| **D1** | **Policy password indebolita** (verificato). Python: `MIN_PASSWORD_LENGTH = 8` (`security/user_manager.py:16`). Go: **6** in `auth_handlers.go:39` (`handleRegister`) e `auth_handlers.go:106` (`handleChangePassword`); in `user_handlers.go` `handleCreateUser` **non c'è alcun controllo di lunghezza**, solo non-vuoto (riga 43). | `internal/api/auth_handlers.go:39,106`; `internal/api/user_handlers.go:43` | Sicurezza. Annulla un hardening già fatto lato Python; sul path admin consente password di 1 carattere. |
| **D2** | **Comandi vendor hardcoded** (verificato): `sess.Run("show version")` e `sess.Run("show running-config")` a riga 47-48, con una `iosVerRe` generica (riga 36), per *qualsiasi* apparato. | `internal/collect/triage.go:36,47-48` | HP vuole `show system`, Juniper `show configuration \| display set`, PAN-OS `show config running`, AireOS `show sysinfo`. Su questi apparati la versione ricade su `firstNonEmptyLine` o `"Non Rilevata"` e il backup è vuoto/errato, **in silenzio**. |
| **D3** | **Riclassificazione uplink solo a scan-time**: il Go marca gli uplink in `macScanDevice`; il Python riclassifica anche in lettura (`_reclassify_sightings`). | `internal/api/mac_handlers.go` | Dopo un cambio di topologia, `is_uplink` resta stale sulle righe vecchie finché non si riscansiona. |
| **D4** | **Colonne mancanti su `devices`**: il CSV Python ha `Site`, `SSH Port`, `Transports`; la tabella Go no. | `internal/store/migrations/0001_init.sql` | Blocca lo scoping per sede (dominio C) e la selezione multi-protocollo (§11.6). |
| **D5** | **`allowed_tabs` non portato**: visibilità per-utente delle tab dashboard. | `internal/store/users.go` | Rotta `/api/users/tabs` assente. |

**D1 va corretto subito** (una riga per sito, nessuna dipendenza). D2 si risolve con la Fase 1 del
dominio B. D4 è un prerequisito condiviso: farlo in Fase 0 evita due migrazioni successive.

---

## 4. Riconciliazione fra i report (contraddizioni risolte)

Le analisi per dominio si sono contraddette su tre punti. Verdetto:

1. **Scoping per tenant — *esiste in parte*.** Il dominio D lo ha dato per mancante, ma A e C hanno
   trovato `App.tenantsForUser(username, role)` e `canSeeTenant` in `internal/api/api.go`, equivalenti a
   `user_group_scope` (`nil` = admin, illimitato). **Quello che manca davvero** è l'helper a livello di
   *device*: `assert_device_allowed` / `assert_group_allowed` di `routers/deps.py`. Va scritto **una sola
   volta** in `internal/api/middleware.go` come `assertDeviceAllowed(ip, claims) (Device, error)` e
   riusato da FortiGate, WLC, AI e observability — non reimplementato per dominio.
2. **VLAN reale nel flowgraph.** Il dominio A ipotizzava un meccanismo VLAN-da-ARP già presente lato Go;
   **non c'è**. Dipende da `arp_entries` del dominio B. Fino ad allora il flowgraph usa il fallback
   sintetico già previsto dal Python (`vlan_real:false`) — comportamento legittimo, non un bug.
3. **`ai/config_analyzer.py`.** Già portato come `internal/configanalyzer/analyzer.go`, ma **solo il ramo
   Cisco IOS**. `detect_config_type` e i rami FortiOS/PAN-OS/AireOS restano scoperti: appartengono al
   dominio B (§5.B), non al D.

---

## 5. Piani per dominio

### 5.A — Observability / Live Flows

Port **da zero** (zero occorrenze di `sflow|ipfix|netflow|observab|flow_aggregates` in `internal/`).

**Semplificazione strutturale.** Il Python dedica un thread OS con un proprio event loop asyncio più
`sys.setswitchinterval(0.001)` **solo per aggirare il GIL**, così che una raffica UDP non affami il
terminale WS e l'API HTTP. In Go **tutto questo sparisce**: le goroutine sono schedulate
preventivamente su thread reali. Per listener servono una goroutine lettrice (`ReadFrom` bloccante →
canale bufferizzato, invio non-bloccante con drop+metrica quando pieno, equivalente di
`put_nowait`/`QueueFull`) e una goroutine consumatrice (parse → attribuzione tenant → enqueue).

**Database separato — si conserva la scelta Python.** `observability.db` resta un file/connessione/set
di migrazioni distinto da `sentinelnet.db`: il volume di scrittura dell'ingest UDP e le DELETE orarie di
retention non devono contendere con letture/scritture di inventory e auth. Diverge dalla convenzione Go
attuale (un solo DB); è deliberato.

```
internal/obsstore/{store.go, writer.go, read.go, migrations/0001_observability_init.sql}
internal/observability/{types.go, metrics.go, manager.go, correlator.go, rollup.go, summary.go}
internal/observability/ingest/{udp.go, ipfix.go, sflow.go, syslog.go, apipoller.go}
internal/api/observability_handlers.go
```

`core/db.py` va portato **insieme** a questo dominio: è il writer singolo a coda limitata
(`enqueue_write`/`enqueue_flow`, batch 500) su cui poggia tutto.

**Ordine**: 1 `obsstore` + migrazione → 2 writer + `EnqueueFlow` (bucketing clock-skew ±300s) →
3 `metrics` → 4 **decoder** (ipfix/sflow/syslog) → 5 `udp.go` → 6 attribuzione tenant + quarantena
(richiede `GetDeviceByIP`) → 7 `manager` (`ApplyConfig` diff, stop-before-start) → 8 `rollup` →
9 `correlator` (`switchPortFor` stub finché B non atterra) → 10 `summary` → 11 handler →
12 `apipoller` (stub `(0, nil)` finché C non atterra) → 13 wiring in `main.go`.

**Il punto duro è il passo 4**: la cache template IPFIX/NetFlow v9 per `(exporter_ip,
observation_domain_id, template_id)`, TTL 1800s, cap 1024 con eviction, più il buffer dei data-set
arrivati prima del template (cap 256, ridecodificati all'arrivo). È logica di protocollo *stateful*: un
errore lì **scarta o attribuisce male i flussi in silenzio**, non crasha.

### 5.B — Driver / Collector / FW-analyzer

```
internal/driver/{driver.go, cisco_ios.go, cisco_cbs.go, cisco_wlc.go, aruba_os.go,
                 hp_procurve.go, juniper_junos.go, fortinet.go, paloalto_panos.go}
internal/arp/{parse.go, collect.go}          + internal/store/arp.go
internal/mac/{+ifmacs.go, parser generico in parse.go}
internal/fwanalyzer/{ip.go, envelope.go, fortios.go, panos.go, convert.go}
```

```go
type Driver interface {
    GetVersion(sess *collect.Session) string  // "Unknown" se non rilevata
    GetBackupCommand() string
    ARPCommand() string
}
```

Ogni driver è ~15 righe (una regex + due stringhe). `RunBackupAndTriage` va parametrizzato su
`driver.Driver` — è la correzione di **D2**. I vendor Fortinet vanno intercettati **prima** del ramo SSH
(sono REST-primary, dominio C).

**Ordine**: 1 `internal/driver` + wiring triage → 2 parser MAC generico + if-macs → 3 `internal/arp` +
tabella `arp_entries` + 4 rotte → 4 `switch_if_macs` + riclassifica in lettura (corregge **D3**) →
5 `fwanalyzer/ip.go` → 6 `fortios.go` → 7 `panos.go` → 8 `detect_config_type` + ramo firewall in
`AnalyzeDevice` → 9 `convert_config` + `POST /api/config-analyzer/convert`.

**Da non portare in v1**: i livelli NETCONF e RESTCONF di `mac_collector.py`. Il CLI copre tutti i vendor
oggi in registro; NETCONF richiederebbe una dipendenza nuova e non banale (RFC 6241 a mano, o
`Juniper/go-netconf`). Isolabili dietro il gate `transports` per-device se mai servissero.

### 5.C — Services (FortiGate, sedi, provisioning, export)

Il dominio con la superficie di rotte più ampia (~45).

```
internal/fortigate/{client.go, tokens.go, ssh.go, observe.go}
internal/wlc/client.go
internal/provision/{switch.go, fortigate.go, secrets.go}
internal/site/{manager.go, jobs.go}
internal/export/visio.go
internal/api/{fortigate_handlers.go, provisioner_handlers.go, sites_handlers.go,
              wlc_handlers.go, agent_handlers.go}
```

**Token e target FortiGate in SQLite, non in JSON.** Il Python usa `data/fortigate_tokens.json`; il port
Go ha già spostato in tabelle ogni altro modulo JSON-backed (`groups.json`, `vendors.json`,
`device_categories.json`). Nuova tabella `fortigate_targets(ip PK, name, port, verify_tls, token_enc,
active)`, con `token_enc` cifrato dal vault esistente.

**Token di sede: hash, non cifratura.** `secrets.token_urlsafe(32)` mostrato una volta sola, persistito
come SHA-256. In Go: `crypto/sha256` + `crypto/subtle.ConstantTimeCompare`. Il vault non c'entra.

**Client REST**: `net/http` puro, `tls.Config{InsecureSkipVerify: !verifyTLS}`, timeout via
`http.NewRequestWithContext`. Nessun retry generico: l'unico fallback è `_api_or_ssh` (REST una volta,
poi SSH), da replicare come sequenza esplicita. I tre messaggi d'errore (certificato self-signed, token
non valido, accprofile insufficiente) sono **user-facing** e vanno portati alla lettera, in italiano come
il resto degli handler.

**Da verificare**: `collect.promptRe` (`[\w.\-/:@()]+[#>]\s*$`) non è provato contro i prompt FortiOS
(`hostname (vdom) #`) né AireOS (`(Cisco Controller) >`). Probabile serva un override per piattaforma.

**Ordine**: 1 `export/visio.go` (indipendente da tutto) → 2 `fortigate/client.go`+`tokens.go`
+ migrazione → 3 `observe.go` rami solo-REST → 4 `ssh.go` + fallback → 5 handler FortiGate →
6 WLC → 7 `provision/switch.go` (solo build) → 8 `secrets.go` → 9 push SSH/seriale →
10 `provision/fortigate.go` → 11 handler provisioner → 12 `site/` + tabelle → 13 handler sites+agent.

**`site_agent.py` non va portato.** È un processo separato che gira sull'hardware remoto e parla solo
HTTP+JSON verso le 5 rotte `/api/agent/*`. Gli agent Python già installati sul campo continueranno a
funzionare contro un server centrale Go **purché il contratto di trasporto resti identico**
(header `X-Site-Id`/`X-Site-Token`, forme JSON, semantica di claim dei job). Portare solo le rotte
riceventi; `cmd/siteagent/` è opzionale e a priorità minima.

### 5.D — AI / MCP / Security residua

```
internal/redact/redact.go
internal/identity/identity.go
internal/crypto/{keystore_windows.go, keystore_other.go}   // build tag
internal/ai/{provider.go, assistant.go, context.go}
internal/mcp/{server.go, client.go}
internal/api/{ai_handlers.go, mcp_handlers.go, mcp_client_handlers.go, identity_handlers.go}
```

**`security/redaction.py` non ha equivalente Go** (zero occorrenze di `redact` in `internal/`). È il
punto di strozzatura unico che rimuove enable secret Cisco, community SNMP, chiavi RADIUS/TACACS+, PSK
WPA, `set psksecret` FortiOS, bearer token e chiavi PEM da qualunque payload diretto a un LLM o a un
server MCP esterno. **Nulla di AI/MCP può andare in produzione prima che esista.** Va portato
regex-per-regex, con fixture di test condivise eseguite contro *entrambe* le implementazioni — non
reimplementato da zero.

**Nessuna dipendenza nuova per AI o MCP.** Il Python stesso non usa SDK: sono 4 chiamate REST grezze
(Anthropic `/v1/messages`, OpenAI `/v1/chat/completions`, Gemini, Ollama) senza streaming né tool-use.
Per MCP la superficie è `initialize` / `notifications/initialized` / `ping` / `tools/list` / `tools/call`
su JSON-RPC 2.0 — il Python la scrive a mano in ~150-530 righe. Si fa lo stesso in Go: niente
`anthropic-sdk-go`, niente `mark3labs/mcp-go`.

**Raccomandazione per la v1:**

- **Portare ora**: `redact`, keystore DPAPI, `identity`. Sono primitive di sicurezza senza dipendenza
  dall'LLM e con valore autonomo.
- **Portare ora, a basso costo**: `/api/mcp/*` (gating dei tool) e il registry server di
  `/api/mcp-client/*`. Sono pannelli di impostazioni che rendono la UI funzionante.
- **Stub in v1**: `internal/ai/*` e le *implementazioni* dei tool MCP. Esporre
  `/api/ai/profiles` (CRUD completo, così il pannello UI non va in 404) e far rispondere
  `/api/ai/chat` e `/api/ai/generate-config` con un chiaro "non disponibile in questa build".

Motivo: è un port di un apparato di rete, il vincolo duro è `dashboard.html` + i contratti JSON.
L'algoritmo di context-budget (`fit_context`/`_filter_relevant_sections`) è la logica più intricata
dell'intero dominio e `/api/ai/chat` dipende dallo scoping per-device di §4.1. Un MCP server i cui tool
danno 404 contro endpoint non ancora portati è peggio di un MCP server assente.

---

## 6. Dipendenze

**L'intero piano aggiunge una sola dipendenza.**

| Necessità | Scelta |
|---|---|
| Porta seriale (`push_via_serial`, `list_serial_ports`) | **`go.bug.st/serial`** ← unica aggiunta. Nessun equivalente stdlib; l'ambiente è Windows 11. Preferito a `tarm/serial` (più mantenuto, ha `enumerator` per `GetPortsList()`). |
| Decoder IPFIX / NetFlow / sFlow | `encoding/binary`. **Nessuna libreria**: `tehmaze/netflow`, `VerizonDigital/vflow`, `bwNetFlow/ipfix` sono non mantenute o portano con sé collector/storage/Kafka propri, incompatibili con il modello attribuzione-tenant + coda limitata + quarantena. Tradurre gli offset a mano è *meno* codice che adattarle. |
| Client REST FortiGate / LLM / MCP | `net/http` + `encoding/json` |
| MCP (server stdio + client HTTP) | scritto a mano su `encoding/json` |
| DPAPI Windows | `golang.org/x/sys/windows` → `crypt32.dll` |
| `.vsdx` | `archive/zip` + `encoding/xml` |
| Goroutine di gruppo | `golang.org/x/sync/errgroup` (già in `go.mod`, primo consumatore) |
| Fernet | non serve: si riusa `internal/crypto` (AES-GCM) |

---

## 7. Divergenze deliberate dal Python

Da mantenere e documentare, non da "correggere":

1. **Ping via TCP:22, non ICMP.** Già scelto in `collect.Ping` per evitare privilegi raw-socket su
   Windows. Vale anche per ARP e scan. Non introdurre `x/net/icmp`.
2. **Niente thread dedicato per l'ingest.** Vedi §5.A — è un workaround del GIL, privo di senso in Go.
3. **Storage in SQLite al posto dei file JSON** per token FortiGate e sedi, coerente con quanto già
   fatto per gruppi/vendor/categorie.
4. **Nessun rollback nel provisioning** — il Python non ce l'ha e il port non deve inventarlo
   (`send_config_set` può lasciare uno switch mezzo configurato). Limite reale: va dichiarato agli
   stakeholder, non nascosto né risolto di straforo.

---

## 8. Schema: migrazioni necessarie

`sentinelnet.db`:

| Migrazione | Contenuto |
|---|---|
| `0004_devices_site_transports.sql` | colonne `site`, `ssh_port`, `transports` su `devices` (**D4**) |
| `0005_arp.sql` | `arp_entries`, `switch_if_macs` |
| `0006_fortigate_sites.sql` | `fortigate_targets`, `sites`, `command_jobs` |
| `0007_identities.sql` | `identities(id, name, tenant, username, password_enc, secret_enc)` |
| `0008_users_tabs.sql` | `allowed_tabs` su `users` (**D5**) |

`observability.db` (nuovo file, migrazioni proprie): `0001_observability_init.sql` — porting quasi
verbatim di `observability/storage/schema.sql` (`flow_aggregates`, `syslog_events`,
`correlated_events`, `api_observations`, `quarantined_exporters`).

Serve inoltre una query `GetDeviceByIP` in `internal/store/inventory.go`: la usano l'attribuzione tenant
dei flussi (A), la cache inventory (C) e `assertDeviceAllowed` (§4.1).

---

## 9. Sequenza consigliata

**Fase 0 — fondamenta condivise** (bloccante per tutto il resto) — ✅ **completata**, vedi §14

- ~~Correggere **D1** (policy password 8 caratteri).~~
- ~~Migrazione `0004` (colonne `devices`).~~ `GetDeviceByIP` **non serve**: `store.GetDevice(ip)`
  interroga già per chiave primaria ed è l'equivalente diretto di `get_device_by_ip`.
- ~~`assertDeviceAllowed` in `middleware.go` (§4.1) — scritto una volta, riusato da A, C, D.~~
- ~~`internal/redact` (§5.D) — prima di qualsiasi egress.~~

Poi quattro tracce parallele, con i punti di giunzione indicati:

```
Traccia 1 (B) driver ──▶ arp/arp_entries ──▶ fwanalyzer ──▶ convert
                              │
                              └──▶ [giunzione: VLAN reale nel flowgraph di A]

Traccia 2 (A) obsstore ─▶ writer ─▶ DECODER ─▶ udp ─▶ manager ─▶ handler
                                                          ▲         ▲
                          [stub switchPortFor] ───────────┘         │
                          [stub apipoller] ───────────────────────  │
                                                                    │
Traccia 3 (C) fortigate client ─▶ observe ─▶ handler ─▶ provision ─▶ sites/agent
                    │
                    └──▶ [giunzione: apipoller reale in A]

Traccia 4 (D) identity + keystore ─▶ MCP settings ─▶ [AI: stub in v1]
```

La traccia 2 è la più lunga e non è bloccata da nessuna altra (gli stub reggono): va avviata per prima.
La traccia 1 sblocca sia D2 sia l'arricchimento VLAN, quindi ha priorità sulla 3.

---

## 10. Strategia di verifica

Il rischio dominante di questo port non è il crash: è la **divergenza silenziosa**. Tre presidi:

1. **Golden file contro l'output Python.** Obbligatori per: le regex dei driver (`show version` per
   vendor, catturati da apparati reali), `BuildSwitchConfig`/`BuildFortiGateConfig` (un ramo `if`
   mancato produce una config sottilmente sbagliata), i parser `fortios`/`panos`.
2. **Parità sui decoder binari.** Catturare datagrammi IPFIX/sFlow reali e farli passare
   attraverso *entrambe* le implementazioni, confrontando i record normalizzati campo per campo.
3. **Fixture condivise per la redazione.** Le stesse config di esempio attraverso `redaction.py` e
   `internal/redact`: qualsiasi differenza è un segreto che trapela.

Nota specifica su Go: il Python garantisce "input malformato non solleva mai, restituisce il
decodificabile e incrementa `parse_errors`". `struct.unpack_from` tollera buffer corti; `encoding/binary`
no. Serve un controllo `if len(buf) < n` esplicito a **ogni** offset — altrimenti si ottiene un panic in
una goroutine listener, che è peggio dell'eccezione catturata del Python (Go non la riavvia).

---

## 11. Stima

| Dominio | Unità | Peso |
|---|---|---|
| A — Observability | 13 | 1×L (decoder), 7×M, 5×S |
| B — Driver/Collector/FW | 10 | 1×L (`convert_config`), 5×M, 4×S |
| C — Services | 13 | 1×L (`observe.go`), 8×M, 4×S |
| D — AI/MCP/Security | 12 | 2×L (`fit_context`, `ai_handlers`), 4×M, 6×S |

Escludendo ciò che §5.D raccomanda di stubbare e §5.B di rimandare (NETCONF/RESTCONF), il perimetro v1
è circa **40 unità**, di cui 3 L.

---

## 12. Rischi principali

| # | Rischio | Mitigazione |
|---|---|---|
| R1 | **Stato dei template IPFIX/NetFlow v9.** Eviction, TTL, maschera enterprise-bit (`ie & 0x8000`), buffer pending. Un errore scarta o attribuisce male i flussi *in silenzio*. | Fixture di byte reali, parità Go↔Python sugli stessi datagrammi. |
| R2 | **Isolamento fra tenant.** `vlans_for_ips` e `client_map` sono per-`(ip, tenant)` **per progetto**: stessi IP RFC1918 esistono in sedi diverse. Una join globale `IN (...)` è una fuga di dati fra tenant. | Preservare il pattern esatto e il chunking (~400) per il limite di 999 parametri di SQLite. |
| R3 | **Scoping per-device sugli endpoint AI.** `attach_device_ip`/`attach_tenant`/`attach_fortigate_ip` senza `assertDeviceAllowed` sono un canale di esfiltrazione. | Fase 0 lo rende prerequisito, non una scoperta a metà port. |
| R4 | **Divergenza dell'API REST FortiOS** fra 6.x e 7.x (posizione di `results`, `format=`, endpoint semi-documentati). | Suite di fixture da JSON reali catturati prima di fidarsi del port. |
| R5 | **Compatibilità con gli agent Python già sul campo.** Continueranno a parlare con il server Go senza redeploy coordinato. | Contratto `/api/agent/*` identico byte-per-byte (header, forme JSON, semantica di claim). |
| R6 | **Fragilità delle regex vendor** fra versioni di firmware. | Replicare alla lettera, mai "migliorare"; golden file da output reale. |
| R7 | **Concorrenza dello scan.** Il Go fonde ping+triage a `SetLimit(32)`; il Python è a due fasi (ping 50 worker, poi SSH solo sui vivi). Su una `/22` quasi morta il Go tenta SSH ovunque. | Riscrivere a due fasi, o documentare la divergenza come scelta. |

---

## 13. Coordinamento fra domini

- `internal/driver` (B) e il campo `driver` del registry vendor (catalog, già portato) non devono
  duplicare la stessa mappa.
- `identity_manager` (D) serve ai path di push SSH del provisioner (C) quando il profilo di un device è
  `identity:<id>`, via `core_engine.get_device_credentials`. **D3 di D precede C11.**
- `command_allowed`/`is_command_safe` (`routers/commands.py`, già in `internal/api/command_safety.go`)
  serve al relay comandi di `sites.py` (C): riusare, non reimplementare.
- `POST /api/map/export/vsdx` appartiene formalmente al dominio topology (già portato) ma la sua unica
  dipendenza è `internal/export/visio.go` (C): una riga di wiring, da concordare.

---

## 14. Registro di avanzamento

### 2026-07-20 — Fase 0 + astrazione driver (D1, D2, D4)

| Intervento | File |
|---|---|
| **D1** — policy password centralizzata a 8 caratteri (`auth.ValidatePassword`), unico punto di verità. Applicata a `handleRegister`, `handleChangePassword` e `handleCreateUser`, che **non aveva alcun controllo di lunghezza**. | `internal/auth/auth.go`, `internal/api/auth_handlers.go`, `internal/api/user_handlers.go` |
| **D4** — migrazione `0004`: colonne `site`, `ssh_port` (default 22), `transports` su `devices` + indice su `site`. `Device` e `UpsertDevice` aggiornati. | `internal/store/migrations/0004_devices_site_transports.sql`, `internal/store/inventory.go` |
| `assertDeviceAllowed` — punto unico lookup+scoping per tenant (porta di `assert_device_allowed`). Applicato a `handleSendCommand`, che duplicava la logica. | `internal/api/middleware.go`, `internal/api/command_handlers.go` |
| `internal/redact` — porta di `security/redaction.py`, 10 pattern replicati alla lettera, `Text()` + `Any()` per payload annidati. Test su ogni pattern, idempotenza e non-alterazione del testo non segreto. | `internal/redact/{redact.go,redact_test.go}` |
| **D2** — `internal/driver`: interfaccia + registro + 8 vendor, regex verbatim dai driver Python. `RunBackupAndTriage` ora riceve un `driver.Driver` e usa `GetVersion`/`BackupCommand` del vendor invece di `show version`/`show running-config` fissi. Risoluzione via `App.driverFor` (campo `driver` del registro vendor → fallback per nome vendor). | `internal/driver/{driver.go,vendors.go,driver_test.go}`, `internal/collect/triage.go`, `internal/api/{jobs.go,command_handlers.go}` |

Note di implementazione:

- `driver.Runner` è un'interfaccia minimale (`Run(string) string`) definita nel package `driver`:
  serve a evitare il ciclo di import `collect → driver → collect`. `*collect.Session` la soddisfa.
- `ResolveOrDefault` ricade su `cisco_ios` per i vendor non riconosciuti, preservando il
  comportamento storico del port Go anziché introdurre un errore dove prima non c'era.
- `driver.IsFortinet` è pronto per intercettare i vendor REST-primary prima del percorso SSH;
  **non è ancora cablato** in `triageDevice` perché il client REST FortiGate (dominio C) non esiste.
- Rimosso `collect.firstNonEmptyLine`, diventato codice morto.

Verifica: `go build ./...` e `go vet ./...` puliti; `go test ./...` verde (inclusi i test API
preesistenti); migrazione `0004` applicata **su una copia del DB reale** con dati preservati,
default corretti e riapertura idempotente.

Aperti da questa fase: **D3** (riclassifica uplink in lettura) e **D5** (`allowed_tabs`).

### 2026-07-20 — Traccia 1, passo 3: raccolta ARP + Client Map

| Intervento | File |
|---|---|
| Migrazione `0005`: tabella `arp_entries` + indice unico `(mac, ip, source_ip)` e indici su mac/ip/tenant/last_seen. | `internal/store/migrations/0005_arp.sql` |
| Parser ARP generico riga-per-riga (porta di `parse_arp_output`): un solo formato copre Cisco, FortiOS, Juniper, PAN-OS. | `internal/arp/{parse.go,parse_test.go}` |
| Layer di persistenza: `RecordARPEntries` (upsert su `(mac,ip,source_ip)`), `SearchARP` (MAC esatto o frammento/OUI, prefisso IP, scoping tenant), `ClientMap`, `ARPStats`, `PruneARP`. | `internal/store/{arp.go,arp_test.go}` |
| 4 rotte `/api/arp/{scan,search,client-map,stats}` con la stessa forma di risposta del Python, scansione concorrente (`SetLimit(8)`) e audit log. | `internal/api/arp_handlers.go`, `internal/api/router.go` |
| Retention ARP agganciata alla prune esistente, come la `prune()` del Python che agisce su entrambe le tabelle. | `internal/api/mac_handlers.go` |

Note di implementazione:

- `store.normalizeMacStrict` è una variante severa di `mac.NormalizeMac`: quest'ultima ritorna
  comunque una stringa su input non valido, mentre `SearchARP` deve distinguere la ricerca esatta
  da quella per frammento (come `normalize_mac`→`None` nel Python). `mac.NormalizeMac` non è stata
  toccata perché usata altrove.
- `accessPositionsFor` usa la chiave composta **`(mac, tenant)`** e interroga a chunk di 400 per
  restare sotto il limite di ~999 parametri di SQLite. È il presidio contro il rischio **R2**:
  con la sola chiave `mac`, la posizione fisica di un tenant finirebbe nel binding ARP di un altro.
  Il test `TestClientMapDoesNotLeakAcrossTenants` fissa esattamente questo scenario.
- Limite noto ereditato dal Python e fissato da un test: la regex MAC non riconosce i formati
  HP/ProCurve `001a4b-2c3d4e` e `001a-4b2c-3d4e`. Estenderla richiede di farlo in **entrambe** le
  implementazioni insieme.
- Anche il filtro broadcast è replicato con la sua stranezza: la sostituzione `'-'`→`':'` del Python
  fa sì che intercetti solo la forma puntata. Documentato in `isDiscardableMAC`, non "corretto".
- I FortiGate restituiscono `status: "error"` con messaggio esplicito: la loro ARP passa dal client
  REST (dominio C, non ancora portato) e inviare un comando CLI sbagliato sarebbe peggio.

Verifica: build, `go vet` e `go test ./...` verdi; migrazione `0005` applicata su copia del DB reale
con round-trip completo (scrittura ARP → `ClientMap` → `ARPStats`).

### 2026-07-20 — Traccia 1, passo 4: `switch_if_macs` + riclassifica in lettura (D3)

| Intervento | File |
|---|---|
| Migrazione `0006`: tabella `switch_if_macs`, chiave `(mac, switch_ip, interface)`. | `internal/store/migrations/0006_switch_if_macs.sql` |
| Parser stateful di `show interfaces` (porta di `parse_cli_if_macs`): l'intestazione fissa l'interfaccia corrente, la riga `address is <mac>` emette la coppia. | `internal/mac/{ifmacs.go,ifmacs_test.go}` |
| `RecordSwitchIfMacs` / `SwitchIfMacs` con canonicalizzazione del MAC. | `internal/store/ifmacs.go` |
| **D3** — `macReclassifier`: ricalcolo in lettura di `is_uplink`/`uplink_to` contro la topologia corrente + tag `origin_type`. Applicato a `/api/mac/search`, `/api/mac/locate` e `/api/mac/switch/{ip}`. | `internal/api/{mac_reclassify.go,mac_reclassify_test.go,mac_handlers.go}` |
| Raccolta dei MAC di interfaccia durante la scansione MAC, non fatale. | `internal/api/mac_handlers.go` |
| Campi calcolati `origin_type` / `origin_switch` / `origin_interface` su `MacSighting` (non persistiti). | `internal/store/mac.go` |

Note di implementazione:

- **Definizione di "switch noto"**: il Python usa i nodi non-`Discovered` della network map;
  qui si considera noto uno switch **per cui esistono dati topologici** (`uplinkInterfaces`
  non vuota). È una deviazione minima ma più aderente all'intento dichiarato dal docstring
  del Python — *«per gli switch senza dati topologici si conserva il valore rilevato in
  raccolta»* — ed evita di azzerare gli uplink su apparati di cui semplicemente non si è
  ancora raccolta la topologia.
- Per gli switch noti la topologia è **autorevole**: l'assenza della porta in mappa significa
  porta di accesso, quindi un `is_uplink` stantio viene azzerato. È esattamente il caso che
  `TestReclassifyClearsStaleUplink` fissa.
- I MAC di infrastruttura si **taggano**, non si scartano: le righe restano nella risposta con
  `origin_type: "switch-interface"`.
- La raccolta di `show interfaces` è deliberatamente non fatale: un errore lì non deve
  compromettere la scansione della MAC-table, che è il dato principale.

Verifica: build, `go vet` e `go test ./...` verdi (il test preesistente
`TestHandleMacLocateSplitsOriginAndTransit` continua a passare, esercitando il ramo di
fallback senza topologia); migrazione `0006` applicata su copia del DB reale con round-trip
scrittura/lettura.

Con questo la parità MAC/ARP con il Python è completa, tranne i livelli NETCONF/RESTCONF
volutamente rimandati (§5.B, punto 10).

### 2026-07-20 — Traccia 2, passi 1-4: fondamenta observability e decoder

| Intervento | File |
|---|---|
| `obsstore`: database separato, migrazione verbatim di `schema.sql`, writer a goroutine singola con commit a batch (500), `EnqueueWrite`/`EnqueueFlow`, `FlowWindowStart`, `Sync`, `Close` che svuota la coda. | `internal/obsstore/{store.go,writer.go,writer_test.go,migrations/0001_observability_init.sql}` |
| Registro metriche thread-safe (contatori, gauge, `ShouldWarn` rate-limited). | `internal/observability/metrics/` |
| Decoder syslog (RFC 3164/5424 + normalizzazione FortiGate e Palo Alto). | `internal/observability/ingest/{syslog.go,syslog_test.go}` |
| Decoder sFlow v5 (solo flow sample; counter sample contati e saltati). | `internal/observability/ingest/{sflow.go,sflow_test.go}` |
| Decoder NetFlow v5/v9 + IPFIX con cache template, TTL, eviction e buffer dei set in attesa. | `internal/observability/ingest/{ipfix.go,ipfix_test.go}` |
| Target di fuzzing per i tre decoder. | `internal/observability/ingest/fuzz_test.go` |

Note di implementazione:

- **Niente thread dedicato per l'ingest**: come previsto in §5.A, il workaround del GIL
  (event loop su thread separato + `sys.setswitchinterval`) non serve in Go.
- **Stato dei template in una struct, non in variabili di modulo**: più listener condividono
  il decoder, e lo stato globale mutabile del Python sarebbe una race in Go.
- **Bounds checking esplicito a ogni offset**: `encoding/binary` non tollera i buffer corti
  come lo slicing Python. Un panic nella goroutine di un listener terminerebbe il processo,
  quindi i test di troncamento e il fuzzing sono il presidio principale (rischio **R2** della
  lista decoder, cioè la parità binaria sotto input malformato).
- I decoder restano **funzioni pure**: i conteggi (`counter_samples_skipped`, `parse_errors`,
  `data_before_template_dropped`) sono restituiti al chiamante invece di scrivere su un
  registro globale, così sono testabili senza dipendenze.
- `Protocol`/`DstPort` valgono `-1` dove il Python emette `None`: la conversione a NULL
  avviene nel wiring di ingest, non nel decoder.

Verifica: build, `go vet` e `go test ./...` verdi; fuzzing ~4,5 M esecuzioni su sFlow e
~700 k su NetFlow/IPFIX (con decoder condiviso, per esercitare l'accumulo di stato) senza crash.

### 2026-07-20 — Traccia 2, passi 5-7 e 11-13: pipeline completa e raggiungibile

| Intervento | File |
|---|---|
| Trasporto UDP: goroutine lettore + consumer per listener, coda limitata con drop, attribuzione tenant, quarantena degli exporter sconosciuti con audit limitato a una voce/ora. | `internal/observability/ingest/{udp.go,udp_test.go}` |
| Manager: `Apply` idempotente con diff e stop-before-start, stato dei listener, bind falliti non bloccanti, loop di retention, `Shutdown`. | `internal/observability/{config.go,manager.go,manager_test.go}` |
| Sink verso il writer + risolutore tenant con cache TTL 60s. | `internal/observability/sink.go` |
| Retention batchata via rowid; eventi correlati aperti mai eliminati. | `internal/obsstore/{rollup.go,rollup_test.go}` |
| Query per top talker, syslog, anomalie, transizione di stato, api-context. | `internal/obsstore/queries.go` |
| 8 rotte `/api/observability/*` + configurazione persistita e applicata a caldo. | `internal/api/{observability_handlers.go,router.go}` |
| Wiring nel ciclo di vita del processo. | `cmd/sentinelnet/main.go`, `internal/api/api.go` |

Note di implementazione:

- **L'osservabilità è opzionale**: se `observability.db` non si apre, l'applicazione parte
  comunque e gli endpoint rispondono 503. È un di più, non una funzione essenziale.
- **Cache del risolutore tenant**: la risoluzione IP→tenant avviene per ogni record
  decodificato, cioè migliaia di volte al secondo sotto carico. Senza cache ogni flusso
  costerebbe una query su SQLite in contesa con il writer. Il Python invalida la cache a
  ogni scrittura dell'inventario; qui un TTL di 60s ottiene lo stesso effetto pratico senza
  agganciarsi a tutti i punti di scrittura.
- **Transizione di stato delle anomalie**: la `UPDATE` include lo stato di partenza, così
  due operatori simultanei non si sovrascrivono in silenzio (il secondo riceve 409). Un
  evento fuori scope ritorna 404 come uno inesistente, per non confermarne l'esistenza.
  Nota: il Python risponde **409** (non 400) a una transizione non ammessa — si è seguito
  il codice, non il riassunto in §5.A.
- Il manager è costruito dentro il package `api` (`EnableObservability`) per non esporre
  il logger di audit.

Verifica: oltre a build/vet/test, il binario è stato eseguito davvero — registrazione admin,
rifiuto di una password da 6 caratteri, attivazione a caldo del listener syslog, invio di due
datagrammi reali (Cisco con timestamp BSD e FortiGate key=value) e rilettura via API con
tenant attribuito, severità e azione corrette. Due test end-to-end coprono lo stesso percorso
in automatico, incluso l'exporter sconosciuto che finisce in quarantena senza scrivere nulla.

### 2026-07-20 — Traccia 2, passi 9 e 11: flowgraph e correlatore

| Intervento | File |
|---|---|
| `GET /api/observability/flowgraph`: nodi/archi con tassi, KPI, riepilogo tenant, ripartizione protocolli. VLAN reale da `arp_entries` con ripiego sintetico dichiarato. | `internal/api/{flowgraph.go,flowgraph_test.go}` |
| `VlansForIPs` con lookup per `(ip, tenant)`. | `internal/store/arp.go` |
| Query per grafo e conteggio anomalie aperte. | `internal/obsstore/queries.go` |
| Correlatore: eventi syslog × flussi × posizione fisica → `correlated_events`, con ciclo periodico. | `internal/observability/{correlator.go,correlator_test.go,manager.go}` |

Note di implementazione:

- **La VLAN sintetica non è un dato falso silenzioso**: quando manca il binding ARP il nodo
  è marcato `vlan_real: false`, così la UI può segnalarlo. Il valore usa sha1 troncato e non
  una hash arbitraria perché deve restare stabile fra riavvii: altrimenti lo stesso tenant
  cambierebbe VLAN, e quindi colore nel grafo, a ogni restart.
- **I byte di un nodo sommano src e dst**: un host solo-destinazione (un server interno mai
  visto come sorgente) resterebbe altrimenti a zero e verrebbe scartato dal taglio ai primi 50.
- Il flowgraph interroga **entrambi i database**: flussi da `observability.db`, binding ARP
  da `sentinelnet.db`.
- Il correlatore è il primo punto in cui i domini portati si incontrano davvero:
  l'arricchimento switch/porta usa la Client Map della traccia 1.
- **Chiave di deduplicazione**: la tupla del flusso replica la rappresentazione Python, così
  un database condiviso fra le due implementazioni non genererebbe doppioni.

Verifica: 9 test sul flowgraph e 8 sul correlatore, inclusi i due casi di isolamento fra
tenant (VLAN di un'altra sede nel grafo; flusso di un altro tenant che "conferma" un evento).

**`summary.go` non è stato portato di proposito**: il suo unico consumatore è il contesto
dell'assistente AI, che §5.D raccomanda di stubbare in v1. Portarlo ora significherebbe
scrivere codice senza chiamanti; va fatto insieme al dominio D, se e quando si porta.

Della traccia 2 resta solo l'**API poller**, bloccato sul client REST FortiGate (traccia 3):
`poll_once` è già stubbabile senza rompere la semantica di `api_poll_s`.

### 2026-07-20 — Traccia 3, passi 2-3: client REST FortiGate

| Intervento | File |
|---|---|
| Migrazione `0007` + persistenza dei target (token cifrato col vault, un solo target attivo). | `internal/store/{fortigate.go,fortigate_test.go,migrations/0007_fortigate_targets.sql}` |
| Client REST FortiOS v2: Bearer token, TLS opt-in, messaggi diagnostici, `GetCMDB` con proiezione, `TestConnection`. | `internal/fortigate/{client.go,client_test.go}` |
| Funzioni di osservabilità con ripiego SSH: 16 endpoint + `apiOrSSH`. | `internal/fortigate/{observe.go,observe_test.go}` |

Note di implementazione:

- **Target in tabella, non in JSON**: coerente con gruppi, vendor, categorie e modelli già
  migrati. Il token è cifrato con lo stesso vault delle password apparato.
- **Token vuoto in aggiornamento = invariato**: rinominare un target o cambiarne la porta non
  deve costringere a reinserire il token ("•••• invariato" lato UI).
- **`apiOrSSH` non è un retry**: un tentativo per trasporto, come il Python. Se falliscono
  entrambi l'errore riporta i due motivi; se la REST fallisce ma l'SSH riesce, il motivo REST
  resta in `api_error`.
- **`monitor/system/status` è l'eccezione**: `version` e `serial` stanno FUORI da `results`.
  Senza fonderli la UI mostrerebbe un FortiGate senza versione.
- **Log di traffico**: si prova prima il disco, poi la memoria — sui modelli senza disco il
  primo tentativo fallisce sempre — e si riporta quale device ha risposto.
- I tre messaggi d'errore (certificato non attendibile, token non valido, accprofile
  insufficiente) sono portati alla lettera: sono la prima cosa che legge un operatore quando
  l'integrazione non funziona.
- I test usano un server TLS con certificato self-signed, così il percorso di verifica è
  esercitato davvero in entrambe le direzioni.

Prossimi passi della traccia 3: gli handler (25 rotte `/api/fortigate/*`, incluso il
`fgtDevice` che riusa `assertDeviceAllowed`), poi WLC, provisioner, sedi/agent e visio export.
Una volta pronto il client, l'**API poller** della traccia 2 si sblocca.

### 2026-07-20 — Traccia 3, passo 4 e traccia 2, passo 8: rotte FortiGate e poller API

| Intervento | File |
|---|---|
| 23 rotte `/api/fortigate/*`: target (token, porta, TLS, test) e osservabilità, tutte via `fgtDevice`. | `internal/api/{fortigate_handlers.go,router.go}` |
| Ripiego SSH dei log di traffico e `filter clear` nel comando CLI delle sessioni. | `internal/fortigate/observe.go` |
| `POST /api/fortigate/{ip}/diagnose-client`: diagnosi aggregata, sette sezioni best-effort, risoluzione MAC→IP. | `internal/fortigate/diagnose.go`, `internal/api/fortigate_handlers.go` |
| Poller REST periodico verso i FortiGate con target configurato. | `internal/observability/{apipoller.go,manager.go}`, `internal/api/api.go` |

Note di implementazione:

- **Due difetti del porting precedente, non divergenze**: `TrafficLogs` aveva perso il
  ripiego CLI, e il comando di `Sessions` non azzerava i filtri prima di impostarli — i
  filtri di sessione sono stato persistente sull'apparato, quindi una diagnosi ereditava
  quelli della precedente e restituiva in silenzio le sessioni sbagliate. Nessuno dei due
  era in `DIVERGENZE-DAL-PYTHON.md`, che è il criterio per distinguere una scelta da un bug.
- **La diagnosi non restituisce mai 502**: ogni sezione porta il proprio errore, e un 502
  direbbe "non so niente" anche con sei sezioni su sette valorizzate.
- **Chiamate sequenziali nella diagnosi**: il ripiego SSH apre una sessione per comando, e
  aprirne quattro in parallelo verso lo stesso apparato è un modo affidabile per farsi
  rifiutare. Il guadagno di latenza non vale il rischio.
- **Il poller non conosce il vault**: riceve una `ClientFunc` da `EnableObservability`. È
  la stessa scelta del logger di audit — il package `observability` non deve poter leggere
  le credenziali.
- Il poller è **REST-only** (divergenza §8): un ripiego SSH su tutto l'inventario a ogni
  giro costerebbe decine di secondi per apparato irraggiungibile.

Verifica: build, `go vet` e `go test ./...` verdi; 9 test sulla diagnosi (di cui 2 sugli
handler) e 7 sul poller. Il race detector non è utilizzabile in questo ambiente perché
richiede cgo e gcc non è installato.

Resta della traccia 3: WLC, provisioner, sedi/agent, visio export. Poi gli analizzatori
firewall (fortios/panos), MCP + AI e il difetto D5 (`allowed_tabs`).

### 2026-07-20 — Traccia 3, passo 5: WLC Cisco

| Intervento | File |
|---|---|
| Logica di piattaforma AireOS / Catalyst 9800: mappa servizio→comando, `NormalizeMAC`, diagnosi aggregata. Package puro, trasporto iniettato come `Runner`. | `internal/wlc/{wlc.go,wlc_test.go}` |
| 8 rotte `/api/wlc/*` con sessione SSH riusata per richiesta. | `internal/api/{wlc_handlers.go,wlc_handlers_test.go,router.go}` |

Note di implementazione:

- **`PagingCommand` è per piattaforma**: AireOS non conosce `terminal length 0`, che è
  esattamente ciò che `collect.Dial` invia a tutti. Senza `config paging disable` un
  `show client summary` su un controller carico si ferma al primo `--More--` e restituisce
  la prima schermata come se fosse l'elenco completo — un errore silenzioso, il peggior tipo.
- **Sessione SSH riusata per richiesta**: il Python riapre la connessione a ogni comando, e
  una diagnosi ne esegue quattro. Stesso risultato, un quarto degli handshake; non è una
  divergenza di comportamento e non è annotata come tale.
- **`NormalizeMAC` è severa**: `internal/mac.NormalizeMac` ritorna l'input invariato quando
  non è un MAC (divergenza §5), e qui un MAC malformato finirebbe in una riga di comando.
  I test verificano che in quel caso nessun comando venga eseguito.
- **`promptRe` non riconosce il prompt AireOS** (`(Cisco Controller) >`, con lo spazio prima
  del `>`): `detectPrompt` ricade sull'ultima riga non vuota, che in pratica funziona. Va
  verificato sul campo insieme al prompt FortiOS, già annotato in d35c975.

Verifica: build, `go vet` e `go test ./...` verdi; 11 test sul package `wlc` e 4 sugli
handler. Gli handler non sono testabili contro un WLC reale, quindi i test coprono il
gating (vendor, 404, 502) e il fatto che la diagnosi risponda 200 anche con SSH assente.

Resta della traccia 3: provisioner (FortiGate e switch), sedi/agent, visio export. Poi gli
analizzatori firewall (fortios/panos), MCP + AI e il difetto D5 (`allowed_tabs`).

### 2026-07-20 — Traccia 3, passo 7: generazione config switch

| Intervento | File |
|---|---|
| `BuildConfig`: running-config IOS/IOS-XE completa, funzione pura. `ConfigCommands` per le sole righe eseguibili. | `internal/provision/switch.go` |
| Golden generati eseguendo il modulo Python su 4 configurazioni. | `internal/provision/testdata/*.{json,txt}` |

Note di implementazione:

- **I golden non sono scritti a mano**: sono l'output vero di
  `services/switch_provisioner.py` su minimale, access completa, distribution con RADIUS e
  TACACS+ con tutti i default disattivati. §1.3 impone la parità 1:1, e un golden inventato
  dimostrerebbe solo che il Go è coerente con sé stesso. Verificato anche che il test sappia
  fallire (alterando `logging buffered` la riga viene segnalata in tutti i casi).
- **I flag di sicurezza sono `*bool`**: nel Python hanno default `True`, e in Go un campo
  assente nel JSON diventa `false`. Con dei `bool` semplici, una chiave non inviata dalla UI
  avrebbe disattivato in silenzio `no vstack`, il blocco anti brute-force, bpduguard e
  l'accesso solo SSH — cioè il contrario di ciò che l'operatore si aspetta da un generatore
  di config "hardened". Due test coprono "assente" contro "false esplicito".
- **Nessun rollback** (§7.4): il Python non ce l'ha e il port non lo inventa.

Prossimi passi: 8 `secrets.go`, 9 push SSH/seriale (unica dipendenza nuova prevista,
`go.bug.st/serial`), 10 `provision/fortigate.go`, 11 handler provisioner, poi sedi/agent.

### 2026-07-20 — Traccia 3, passi 8-10: segreti, consegna e provisioner FortiGate

| Intervento | File |
|---|---|
| Mascheramento dei segreti nel payload del wizard (finding I-2). | `internal/provision/{secrets.go,secrets_test.go}` |
| Consegna via SSH e console seriale, elenco porte COM. | `internal/provision/{push.go,push_test.go}` |
| `Credentials.Port` per il day-0 su porta SSH non standard. | `internal/collect/ssh.go` |
| Generazione config day-0 FortiOS. | `internal/provision/{fortigate.go,fortigate_test.go}` |
| Golden dal Python per mascheramento e FortiGate. | `internal/provision/testdata/{secrets,fortigate}/` |

Note di implementazione:

- **Il mascheramento lavora sul payload generico**, non sulla struct tipizzata: è lo stesso
  `map[string]any` che il Python maschera, vale per entrambi i provisioner senza elencarne i
  campi, e un campo nuovo aggiunto domani è coperto per costruzione. Il percorso nei
  placeholder non è indicizzato per le liste (`{{VAULT:aaa_servers.key}}` per ogni elemento):
  comportamento del Python, verificato eseguendolo.
- **`go.bug.st/serial` è l'unica dipendenza nuova** prevista da §6, ed è puro Go: il binario
  statico senza CGO continua a compilare (verificato, ~20 MB).
- **`serialScript` è separata dall'I/O**: senza hardware è l'unica parte testabile del
  percorso seriale, ed è quella che conta, perché su una console non c'è prompt-matching e i
  comandi vanno a tempo.
- **I flag con default True restano `*bool`** in entrambi i provisioner. Sul FortiGate sono
  cinque (`strong_crypto`, `lockout`, `disable_wan_admin`, `rest_api_logging`,
  `lan_to_wan_policy`) e un `bool` semplice avrebbe disattivato in silenzio la crittografia
  forte e la chiusura dell'accesso admin dal WAN su un firewall esposto.
- **Nessun rollback** in nessuno dei due percorsi di consegna (§7.4).

Difetto trovato e corretto: il test golden delle config glob-a `testdata/*.json`, e le
fixture del mascheramento aggiunte lì non avevano un `.txt` corrispondente. Ora le fixture
stanno in sottocartelle. Era sfuggito perché dopo quel commit erano stati eseguiti solo i
test del mascheramento e non l'intero package — il test funzionava, non era stato lanciato.

Verifica: build statico, `go vet` e `go test ./...` verdi su 16 package. I golden FortiGate
sono stati rigenerati dal Python e confrontati dopo l'implementazione, per escludere che
fossero stati adattati al codice invece del contrario.

Prossimi passi: 11 handler provisioner (`/api/provisioner/*`), poi 12-13 `site/` + sedi/agent,
visio export, analizzatori firewall, MCP + AI e il difetto D5.

### 2026-07-20 — Traccia 3, passo 11: rotte del provisioner (day-0 completo)

| Intervento | File |
|---|---|
| Consegna FortiOS: REST API (config-script base64), SSH, console seriale. | `internal/provision/fortigate_push.go` |
| 9 rotte `/api/provisioner/*` per switch e FortiGate. | `internal/api/{provisioner_handlers.go,router.go}` |
| Golden mancante: WAN senza `wan_mode` (default "dhcp"). | `internal/provision/testdata/fortigate/wan_mode_default.*` |

Note di implementazione:

- **FortiOS non è lo switch Cisco** su due punti che contano: il commento è `#` e non `!`
  (serve un filtro dedicato, altrimenti i commenti passano e la CLI li rifiuta uno per uno)
  e la config è salvata a ogni `end` — quindi niente `write memory`, che sarebbe un comando
  sconosciuto, e nessun `configure terminal` attorno a un testo che contiene già i propri
  `config ... end`.
- **Gli handler lavorano sul payload generico**: il mascheramento ragiona sui nomi delle
  chiavi, la struct tipizzata serve solo a generare il testo.
- **Le tre garanzie del finding I-2 hanno un test ciascuna**: mascheramento di default,
  materializzazione esplicita e auditata (solo il valore `true` materializza, così un
  parametro malformato ricade sul comportamento sicuro), e push che applica i segreti reali
  ma restituisce al client la versione con i placeholder. L'ultima è verificata dall'esterno,
  sull'ordine reale delle chiamate: se `MaskSecrets` mutasse il payload, l'apparato
  riceverebbe i placeholder al posto delle password.
- Sul FortiGate il push prova **REST API e poi SSH**, come l'osservabilità; `method` e
  `api_error` dicono quale canale ha funzionato e perché il primo non è bastato.

Verifica: build statico, `go vet` e `go test ./...` verdi su 16 package; 10 test sugli
handler del provisioner.

**Il provisioning è completo** (passi 7-11). Prossimi passi: 12-13 `site/` + tabelle e le
rotte sedi/agent (`site_agent.py` non va portato: solo le rotte riceventi, vedi §5.C), poi
visio export, analizzatori firewall (fortios/panos), MCP + AI e il difetto D5.

### 2026-07-20 — Traccia 3, passi 12-13: sedi multi-sito e agenti

| Intervento | File |
|---|---|
| Migrazione 0008: tabelle `sites` e `command_jobs`, con la sede 'central' precaricata. | `internal/store/migrations/0008_sites_jobs.sql` |
| CRUD sedi, token hashato, autenticazione a tempo costante. | `internal/store/{sites.go,sites_test.go}` |
| Coda dei job: enqueue, claim transazionale, completamento con verifica di sede. | `internal/store/{jobs.go,jobs_test.go}` |
| Migrazione 0009: colonna `site` sugli avvistamenti MAC. | `internal/store/migrations/0009_mac_site.sql` |
| 8 rotte sedi/job + 5 rotte agente. | `internal/api/{sites_handlers.go,agent_handlers.go,agent_handlers_test.go,router.go}` |

Note di implementazione:

- **Tabelle in `internal/store`, non in un package `internal/site`** come da schizzo §5.C: nel
  codice Go esistente è lo store a possedere le tabelle, e la coerenza con quanto già scritto
  vale più dello schizzo.
- **Il token di sede è un hash SHA-256, non un valore cifrato**: non deve essere recuperabile
  nemmeno da chi ha la chiave del vault. `tokenHash` è un campo non esportato, quindi non può
  finire in una risposta JSON per distrazione.
- **Confronto a tempo costante senza uscita anticipata**: un confronto normale termina al primo
  byte diverso, e un `break` al primo riscontro renderebbe il tempo di risposta dipendente dalla
  posizione della sede in elenco.
- **`ClaimPendingJobs` è transazionale**: due agenti della stessa sede in polling contemporaneo
  eseguirebbero altrimenti lo stesso comando due volte su un apparato.
- **Il push di inventario preserva il tenant esistente**: senza, ogni ciclo declasserebbe a
  'Generale' i dispositivi attribuiti a un cliente.

Difetti trovati e corretti: `mac_sightings` non aveva la colonna `site` (il Python ce l'ha e la
usa come filtro), quindi l'attribuzione per sede — il motivo per cui esiste la modalità agent —
andava persa. Documentata inoltre la **divergenza §9**: la blacklist CLI in Go non ha il bypass
admin del Python (audit M-1). Era già così in `handleSendCommand` ma non era annotata: era un
difetto, non una scelta. Regolarizzata e non "corretta" perché la direzione è quella sicura, ma
**va decisa dagli stakeholder** — finché non lo è, `cli_blacklist_operators` non ha effetto.

Verifica: build statico, `go vet` e `go test ./...` verdi su 16 package; 20 test sullo store e
8 sulle rotte agente, concentrati sul confine di autenticazione (token errato, X-Site-Id non
corrispondente, sede passata a central, job di un'altra sede).

Resta: visio export, analizzatori firewall (fortios/panos), MCP + AI e il difetto D5.

### 2026-07-20 — M-1 completo e superficie delle impostazioni chiusa

| Intervento | File |
|---|---|
| `commandAllowed` per ruolo + `isBulkCommandAllowed`, applicati a send-command, bulk, relay e terminale WS. | `internal/api/{command_safety.go,command_handlers.go,sites_handlers.go,ws_handlers.go}` |
| 6 rotte: `/api/settings/{cli-blacklist,fortigate-preview,app}`. | `internal/api/{settings_handlers.go,router.go}` |

Note di implementazione:

- **M-1 riguardava quattro punti, non uno**: `command_allowed` nel Python è applicato a
  send-command, bulk, relay di sede e terminale WebSocket. Portarne uno solo avrebbe lasciato
  il terminale più severo delle API — un admin poteva riavviare via API ma non digitandolo.
- **Il bulk non ha bypass per nessuno**, come nel Python: lista separata e più corta, perché
  lì il comando parte verso decine di apparati insieme.
- **Solo `"false"` disattiva la blacklist**: chiave assente, vuota o malformata la lasciano
  attiva. Un dato illeggibile non deve spegnere una protezione.
- **`/api/settings/app` espone solo `port`** (divergenza §9): TLS, CORS e no_browser non
  esistono nel server Go, e le finestre di retention appartengono alla configurazione
  dell'osservabilità. Le chiavi non gestite sono rifiutate con 400 invece di essere accettate
  e ignorate. `port` è onorato davvero da `ResolveListenAddr`, con test end-to-end dalla POST
  all'indirizzo risolto.

Difetto trovato e corretto: `handleBulkCommand` non aveva **nessun** controllo sui comandi
distruttivi, mentre il Python blocca reload/reboot/erase/format/write erase senza bypass. Era
la lacuna più seria fra quelle emerse, perché l'invio massivo non si ferma al primo apparato.

Verifica: build statico, `go vet` e `go test ./...` verdi su 16 package; 15 test fra sicurezza
dei comandi e rotte di impostazioni.

Resta: visio export, analizzatori firewall (fortios/panos), MCP + AI e il difetto D5.

### 2026-07-20 — Difetto D5 chiuso; visio export rinviato

| Intervento | File |
|---|---|
| `allowed_tabs` per-utente: migrazione, store, /me, /users, POST /api/users/tabs. | `internal/store/{users.go,migrations/0010_users_tabs.sql}`, `internal/api/{auth_handlers.go,user_handlers.go,router.go}` |

Note di implementazione:

- **D5 era l'ultimo difetto aperto**: tutti i D1-D5 sono ora corretti.
- **Enforcement solo lato frontend**, come dichiara il Python: `allowed_tabs` nasconde i
  pulsanti delle tab, non protegge le API — quelle restano vincolate da ruolo e sede. Per
  questo la lettura tollera valori illeggibili tornando "nessuna restrizione": è una
  preferenza di interfaccia e non deve poter bloccare il login.
- **Gli admin non sono mai ristretti**: `/me` ritorna lista vuota anche con tab salvate,
  altrimenti un admin potrebbe auto-nascondersi delle tab senza modo di rimetterle.

**Visio export rinviato per decisione dell'utente**: la rotta `/api/map/export/vsdx`
(`services/visio_export.py`, 551 righe, genera un `.vsdx` = zip OPC + XML) non è portata.
Il metodo golden non si applica — i byte del `.vsdx` non sono consumati dalla dashboard ma
scaricati e aperti in Visio — e in questo ambiente non c'è Visio per verificare che il file
si apra davvero. Va ripreso quando la verifica è possibile. Il contratto JSON in ingresso
(`{nodes, edges, primitives, connectors}` dal frontend) è già noto e non cambia.

Resta della traccia 3/dominio D: **visio export** (rinviato), **analizzatori firewall
fortios/panos**, **MCP + AI**.
