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

> **Stato al 2026-07-20**: **D1, D2, D3 e D4 sono corretti** (vedi §14). Resta aperto solo **D5**.

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

Prossimo passo naturale: traccia 2 (observability), che non è bloccata da nulla — gli stub per
`switchPortFor` e per l'API poller reggono finché le tracce 1 e 3 non atterrano. In alternativa
la traccia 1 prosegue con `internal/fwanalyzer` (passi 5-7).
