# SentinelNet — Piano di port in Go

Piano per riscrivere SentinelNet (attuale: Python/FastAPI) in Go, mantenendo
parità di funzionalità e riutilizzando il frontend esistente.

## 0. Branch o nuovo repo?

**Raccomandazione: nuovo repo** (`sentinelnet-go`), non un branch.

Motivi: è una riscrittura di linguaggio, non un refactor — moduli, build, CI,
`.gitignore` e tooling sono completamente diversi; tenere Python e Go nello stesso
branch crea confusione e history sporca. Un nuovo repo dà layout Go pulito,
release/CI indipendenti e cross-compile senza attriti.

Alternativa (branch `go-port` nello stesso repo) solo se serve: side-by-side per
confronto diretto file-per-file durante il port, o migrazione "strangler" con
i due backend che girano in parallelo dietro lo stesso reverse proxy. In tal caso
mettere il codice Go sotto `./go/` per isolarlo.

Il frontend (`templates/dashboard.html`) va **copiato as-is** nel nuovo repo ed
embeddato (vedi §3): non si riscrive la UI.

## 1. Obiettivo e perché Go

Parità di funzionalità con l'attuale: inventario apparati multi-tenant, backup +
triage via SSH, topologia CDP/LLDP, MAC Tracker (NETCONF/RESTCONF/CLI + comandi
ad-hoc), threat intel EUVD, RBAC/JWT, UI bilingue.

Vantaggi del port:
- **Binario unico statico** (Windows/Linux) — niente runtime Python né PyInstaller.
- **Concorrenza nativa**: goroutine + worker pool per polling parallelo degli
  apparati (oggi `ThreadPoolExecutor`), con backpressure pulita.
- **Cross-compile** banale (`GOOS/GOARCH`).
- **Storage unificato in SQLite** (elimina lo sparpagliamento JSON/CSV attuale).

Trade-off da mettere in conto:
- L'ecosistema di automazione di rete in Go è **meno ricco** di Python
  (Netmiko/ncclient sono Python-first). Serve validare le librerie Go contro il
  parco reale (Catalyst, CBS `cisco_s300`, C8000V bridge-domain).
- Interop crittografica per **migrare le password apparati** (Fernet Python).

## 2. Stack tecnologico (mappatura dalle dipendenze attuali)

| Ambito | Python (oggi) | Go (proposto) |
|---|---|---|
| HTTP | FastAPI + uvicorn | `net/http` + `go-chi/chi` (router idiomatico, leggero) |
| Validazione | pydantic | struct + `go-playground/validator` |
| Auth JWT | pyjwt | `github.com/golang-jwt/jwt/v5` |
| Password hashing | bcrypt | `golang.org/x/crypto/bcrypt` |
| DB | sqlite3 + JSON/CSV | **`modernc.org/sqlite`** (SQLite puro-Go, **no CGO** → binario unico) |
| SSH/CLI scraping | netmiko / paramiko | **`github.com/scrapli/scrapligo`** (driver CLI, analogo Netmiko) + `golang.org/x/crypto/ssh` |
| NETCONF | ncclient | `scrapligo` (driver netconf) oppure `github.com/nemith/netconf` |
| RESTCONF | requests | `net/http` client |
| WebSocket (CLI) | websockets | `github.com/coder/websocket` (o `gorilla/websocket`) |
| HTTP client (EUVD) | requests | `net/http` |
| Crypto vault | cryptography (Fernet) | AES-GCM (`crypto/aes`+`crypto/cipher`) o `filippo.io/age` |
| Key at-rest (Windows) | DPAPI via ctypes | `github.com/billgraziano/dpapi` |
| Logging | logging | `log/slog` (stdlib) |
| Frontend asset | FileResponse | `embed.FS` (go:embed) |
| Packaging | PyInstaller | `goreleaser` + `Dockerfile` multi-stage |

Le rotte HTTP e i contratti JSON **restano identici** (`/api/...`) così il
`dashboard.html` esistente funziona senza modifiche ai `fetch`.

## 3. Layout del progetto (idiomatico Go)

```
sentinelnet-go/
  cmd/sentinelnet/main.go        # entrypoint, wiring, flag/env
  internal/
    api/        router, middleware (auth JWT, tenant scoping, lockout), handlers
    auth/       jwt, bcrypt, users, ruoli (admin/operator/viewer)
    store/      layer SQLite: devices, tenants, users, versions, categories,
                vendors, models, mac_sightings, mac_overrides, settings
    collect/    driver CLI/SSH (scrapligo), risoluzione driver per-vendor
    netconf/    client netconf + parser
    restconf/   client restconf
    mac/        collector MAC + parser (matm-oper, openconfig, bridge-domain, cli),
                normalizzazione, uplink filter, retention
    topology/   parse CDP/LLDP, port-channel, VTP, generazione mappa/classificazione
    euvd/       proxy ENISA EUVD (whitelist param, cap size 100)
    crypto/     vault password + key store (env → DPAPI/AES file)
    config/     path, env (SENTINELNET_DATA_DIR, *_MASTER_KEY, *_JWT_SECRET)
  web/          dashboard.html + eventuali asset (embed.FS)
  migrations/   schema SQL versionato
  tools/import/ migratore one-shot dai dati Python (§6)
  Dockerfile  .goreleaser.yaml  Makefile
```

## 4. Concorrenza (sostituzione del ThreadPool)

- Worker pool con `golang.org/x/sync/errgroup` + `SetLimit(N)` per triage,
  ping-check, MAC scan: N goroutine concorrenti con limite (es. 8–16).
- `context.Context` per timeout/cancellazione per-apparato (oggi `timeout` netmiko).
- Scritture DB serializzate dalla connessione SQLite (WAL) — come oggi il `_io_lock`.

## 5. Mappatura funzionalità → pacchetti (con note di rischio)

| Funzione (Python) | Pacchetto Go | Note / rischio |
|---|---|---|
| `security_manager` (JWT, lockout, audit) | `auth`, `api/middleware` | diretto |
| `user_manager` (utenti, ruoli, must_change_password) | `auth` + `store` | diretto |
| `inventory_manager` (devices/tenants/categorie/vendor/model) | `store` | **migra tutto a SQLite** invece di JSON/CSV |
| `crypto_vault` + `secure_key_store` (DPAPI) | `crypto` | Fernet→AES-GCM; DPAPI via lib; **interop per migrazione** |
| `core_engine.run_backup_and_triage` | `collect` (scrapligo) | validare parità comandi per-vendor |
| `parse_cdp_lldp_neighbors`, mappa, VTP, port-channel | `topology` | port dei regex/parser (table-driven test) |
| `mac_collector` (matm-oper→openconfig→cli, bridge-domain, generic) | `mac` | matm-oper **resta primario**; port dei parser 1:1 |
| `mac_history` (SQLite, retention, overrides, ricerca) | `store`/`mac` | già SQLite: port quasi diretto |
| EUVD proxy `/api/search` | `euvd` | banale in Go |
| CLI WebSocket terminal | `api` + `collect` | bridge WS↔SSH; gestire PTY/interattività |
| `dashboard.html` (UI, i18n, tab) | `web` (embed) | **riuso as-is** |

## 6. Migrazione dati (decisione chiave)

Tool `tools/import` one-shot che legge i file attuali e popola SQLite:
`network_hosts.csv`, `users.json`, `groups.json`, `device_categories.json`,
`detected_versions.json`, `vendors.json`, `device_models.json`, `mac_history.db`.

**Punto critico — password apparati**: sono cifrate con Fernet (Python). Opzioni:
1. Il migratore decifra col vecchio schema (reimplementare Fernet in Go: è
   AES-128-CBC + HMAC-SHA256 su chiave base64 — fattibile) e ricifra con AES-GCM.
2. Più semplice/robusto: **re-provisioning** delle credenziali nel nuovo sistema
   (l'inventario e tutto il resto migrano; solo le password si re-inseriscono).

Gli hash bcrypt degli **utenti** sono compatibili as-is (stesso bcrypt) → nessun
re-login forzato.

## 7. Fasi di consegna (milestone)

- **F0 — Scaffold**: repo, go.mod, `embed` di dashboard.html, config/env, schema
  SQLite + migrazioni, `/healthz`. *(sblocca tutto)*
- **F1 — Auth**: JWT, bcrypt, utenti, ruoli, tenant scoping, lockout, setup wizard.
- **F2 — Inventario**: CRUD device/tenant, import/export CSV, servire la UI, rotte
  di lettura (`/api/local-devices`, ecc.). A questo punto la UI "si accende".
- **F3 — Collect**: SSH/CLI (scrapligo) → backup + triage + version detection, in
  parallelo (worker pool).
- **F4 — Topologia**: parser CDP/LLDP, mappa, classificazione, port-channel, VTP.
- **F5 — MAC Tracker**: NETCONF/RESTCONF/CLI (matm-oper primario, OpenConfig,
  bridge-domain ad-hoc, multi-select, retention, ricerca).
- **F6 — Threat Intel**: proxy EUVD.
- **F7 — CLI WebSocket**: terminale interattivo.
- **F8 — Crypto & packaging**: key store (env→DPAPI/AES), goreleaser, Docker.
- **F9 — Migrazione + parità**: tool import, test di parità contro il lab CML
  (192.168.31.9 e switch reali).

Ordine pensato per avere una UI funzionante presto (F2) e ridurre il rischio sul
collect/parse (F3–F5), che è la parte meno "standard" in Go.

## 8. Testing

- **Table-driven test** sui parser (porto i casi già validati: matm-oper JSON/XML,
  OpenConfig JSON/XML, `show mac address-table`, `show bridge-domain`, CDP/LLDP,
  port-channel/VTP) usando golden file.
- **Integrazione** contro il device CML NETCONF/RESTCONF/CLI del lab.
- Test contract sulle rotte per garantire che il `dashboard.html` esistente resti
  compatibile (stessi JSON).

## 9. Rischi principali (sintesi)

1. Parità driver di rete: scrapligo/netconf da validare su CBS e C8000V bridge-domain.
2. Interop Fernet per migrare le password (o re-provisioning).
3. DPAPI in Go su Windows (lib esistente, ma da testare).
4. Terminale CLI interattivo via WebSocket (PTY) — la parte più delicata.
5. `dashboard.html` resta un monolite: riuso pragmatico ora, eventuale refactor UI
   come lavoro separato futuro (non in questo port).

## 10. Come iniziare (primi comandi)

```bash
# nuovo repo
mkdir sentinelnet-go && cd sentinelnet-go && git init
go mod init github.com/<org>/sentinelnet-go
# copiare la UI
cp ../SentinelNet/templates/dashboard.html web/dashboard.html
# scaffold F0: main.go, config, store (schema+migrazioni), embed, /healthz
```

---

## 11. Contratto delle rotte (parità 1:1 con l'attuale FastAPI)

Livelli auth: **pub** (nessuna) · **auth** (viewer+) · **op** (admin+operator) · **adm** (admin).
Il frontend consuma questi path invariati: mantenerli identici è vincolante.

| Metodo | Path | Auth | Note |
|---|---|---|---|
| GET | `/` | pub | serve `dashboard.html` (embed) |
| GET | `/api/auth/status` | pub | `{has_users}` |
| POST | `/api/auth/register` | pub* | *solo se nessun utente: crea primo admin |
| POST | `/api/auth/login` | pub | `{access_token, token_type, role, must_change_password}` |
| POST | `/api/auth/change-password` | auth | self; azzera `must_change_password` |
| GET | `/api/auth/me` | auth | `{username, role}` |
| GET | `/api/users` | adm | |
| POST | `/api/users` | adm | crea con `must_change_password=true` |
| POST | `/api/users/delete` · `/role` · `/disable` · `/groups` | adm | mantieni ≥1 admin |
| GET | `/api/local-devices` | auth | `{devices, groups, detected_versions}` (scoped) |
| GET | `/api/export/devices` | auth | CSV |
| POST | `/api/add-device` · `/delete-device` · `/rename-device` · `/reassign-device` · `/import-csv` | op | scoping tenant |
| GET | `/api/groups` | auth | |
| POST | `/api/groups` · `/groups/rename` · `/groups/delete` | op | "Generale" protetto |
| GET | `/api/vendors` | auth | merge default+custom |
| POST | `/api/vendors` · `/vendors/delete` | op | |
| GET | `/api/device-classification` | auth | nodi + conteggi (map+meta) |
| POST | `/api/device-categories` · `/delete` · `/delete-subcategory` · `/assign` | op | |
| POST | `/api/promote-device` | op | eredita nome/model/ver |
| GET | `/api/models` | auth | |
| POST | `/api/models` · `/models/delete` | op | |
| GET | `/api/topology` · `/network-map` · `/portchannels` (`?group=`) | auth | scoped |
| POST | `/api/topology/reset` | op | |
| POST | `/api/run-triage` · `/triage/{ip}` | op | job async |
| GET | `/api/triage-status` | auth | |
| POST | `/api/send-command` · `/bulk-command` | op | |
| GET | `/api/bulk-command/{job_id}` | auth | polling job |
| POST | `/api/ping-check` · GET `/api/ping/{ip}` | op | |
| POST | `/api/ws-token` | op | OTP breve per la WS |
| WS | `/api/ws-terminal/{ip}` | token | terminale CLI |
| GET | `/api/download-backup/{ip_or_filename}` | op | path-safe |
| GET | `/api/search` | auth | proxy EUVD (whitelist param, size≤100) |
| POST | `/api/mac/scan` | op | `{group, ip?, ips[], transport?}` |
| GET | `/api/mac/search` · `/mac/switch/{ip}` · `/mac/stats` | auth | scoped |
| POST | `/api/mac/settings` | adm | retention |
| GET | `/api/mac/overrides` | auth | |
| POST | `/api/mac/overrides` · `/overrides/delete` | op | |
| POST | `/api/scan-subnet` | op | job async |
| GET | `/api/scan-subnet/{job_id}` | auth | polling |

Job async (triage / bulk-command / scan-subnet): in Go usare una `map[string]*Job`
protetta da `sync.Mutex` (o `sync.Map`) con goroutine di lavoro — equivalente ai
dict `_scan_jobs`/`_bulk_jobs` attuali.

## 12. Schema SQLite completo (migrations/0001_init.sql)

```sql
PRAGMA journal_mode=WAL;

CREATE TABLE users (
  username           TEXT PRIMARY KEY,
  hashed_password    TEXT NOT NULL,
  role               TEXT NOT NULL DEFAULT 'viewer',   -- admin|operator|viewer
  disabled           INTEGER NOT NULL DEFAULT 0,
  must_change_password INTEGER NOT NULL DEFAULT 0
);
-- sedi/tenant visibili per utente (vuoto = tutti)
CREATE TABLE user_tenants (username TEXT, tenant TEXT,
  PRIMARY KEY(username, tenant));

CREATE TABLE tenants (                                 -- ex "groups"
  name        TEXT PRIMARY KEY,
  description TEXT DEFAULT ''
);

CREATE TABLE devices (
  ip               TEXT PRIMARY KEY,
  vendor           TEXT NOT NULL,
  profile          TEXT DEFAULT 'custom',
  username         TEXT DEFAULT '',
  password_enc     TEXT DEFAULT '',                    -- AES-GCM (vedi §6)
  enable_secret_enc TEXT DEFAULT '',
  tenant           TEXT NOT NULL DEFAULT 'Generale',
  hostname         TEXT DEFAULT ''
);

CREATE TABLE detected_versions (
  ip         TEXT PRIMARY KEY,
  vendor     TEXT, version TEXT, status TEXT,
  updated_at TEXT
);

CREATE TABLE categories (key TEXT PRIMARY KEY, label TEXT, builtin INTEGER DEFAULT 0);
CREATE TABLE subcategories (category TEXT, name TEXT, PRIMARY KEY(category, name));

-- assegnazioni/override manuali per nodo (ex category_assignments)
CREATE TABLE device_meta (
  node_id     TEXT PRIMARY KEY,   -- IP o "discovered_<host>"
  category    TEXT, subcategory TEXT, vendor TEXT, model TEXT,
  ha_group    TEXT, name TEXT, ver TEXT
);

CREATE TABLE vendors (name TEXT PRIMARY KEY, euvd_term TEXT, driver TEXT);
CREATE TABLE models  (vendor TEXT, model TEXT, PRIMARY KEY(vendor, model));

CREATE TABLE mac_sightings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mac TEXT NOT NULL, oui_vendor TEXT DEFAULT '', vlan TEXT DEFAULT '',
  switch_ip TEXT NOT NULL, switch_name TEXT DEFAULT '',
  interface TEXT DEFAULT '', port_channel TEXT DEFAULT '',
  is_uplink INTEGER DEFAULT 0, tenant TEXT DEFAULT '',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, seen_count INTEGER DEFAULT 1
);
CREATE UNIQUE INDEX ux_mac_pos ON mac_sightings(mac, switch_ip, interface, vlan);
CREATE INDEX ix_mac ON mac_sightings(mac);
CREATE INDEX ix_switch ON mac_sightings(switch_ip);
CREATE INDEX ix_last_seen ON mac_sightings(last_seen);
CREATE INDEX ix_tenant ON mac_sightings(tenant);

CREATE TABLE mac_cmd_overrides (switch_ip TEXT PRIMARY KEY, command TEXT NOT NULL, fmt TEXT DEFAULT 'generic');
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);  -- es. mac_retention_days
```

I backup config restano **file** in `backup-config/<tenant>/<host>-<ip>.txt` (non in DB).
`audit.log` resta file append-only (o tabella `audit_log` se si preferisce).

## 13. Kit di scaffold F0 (eseguibile allo step 1)

**go.mod / dipendenze**
```bash
go mod init github.com/<org>/sentinelnet-go
go get github.com/go-chi/chi/v5
go get github.com/golang-jwt/jwt/v5
go get golang.org/x/crypto/bcrypt golang.org/x/crypto/ssh
go get modernc.org/sqlite
go get github.com/scrapli/scrapligo
go get github.com/coder/websocket
go get golang.org/x/sync/errgroup
# Windows-only (build tag): go get github.com/billgraziano/dpapi
```

**Albero minimo F0**
```
cmd/sentinelnet/main.go
internal/config/config.go     # env: SENTINELNET_DATA_DIR, _MASTER_KEY, _JWT_SECRET, ADDR
internal/store/store.go       # open SQLite (WAL), applica migrations via embed
internal/store/migrations/0001_init.sql
internal/api/router.go        # chi router, /healthz, static embed, gruppi rotte (stub)
web/dashboard.html            # copiato dall'app Python
web/embed.go                  # //go:embed dashboard.html -> fs.FS
go.mod  .gitignore  Makefile  Dockerfile  .goreleaser.yaml
```

**main.go (traccia)**
```go
func main() {
    cfg := config.Load()
    db := store.MustOpen(cfg.DBPath())          // WAL + migrations
    r := api.NewRouter(cfg, db)                  // /healthz, static, /api/... (stub)
    srv := &http.Server{Addr: cfg.Addr, Handler: r}
    // graceful shutdown su SIGINT/SIGTERM
    go func() { _ = srv.ListenAndServe() }()
    /* wait signal */ _ = srv.Shutdown(context.Background())
}
```

**web/embed.go**
```go
package web
import "embed"
//go:embed dashboard.html
var Files embed.FS
```

**.gitignore (Go + dati locali)**
```
/sentinelnet-go
*.exe
/dist/
sentinelnet.db  sentinelnet.db-wal  sentinelnet.db-shm
mac_history.db*
backup-config/
*.key  secret.key  jwt_secret.key
.env  .env.*
```

**Makefile (essenziale)**
```make
run:   ; go run ./cmd/sentinelnet
build: ; CGO_ENABLED=0 go build -o sentinelnet ./cmd/sentinelnet
test:  ; go test ./...
```

**Dockerfile (multi-stage, binario statico)**
```dockerfile
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /sentinelnet ./cmd/sentinelnet
FROM gcr.io/distroless/static-debian12
COPY --from=build /sentinelnet /sentinelnet
EXPOSE 8000
ENTRYPOINT ["/sentinelnet"]
```

**Criterio di "F0 done"**: `make run` avvia il server, `GET /` restituisce la
dashboard (embed), `GET /healthz` → 200, il DB SQLite viene creato con lo schema
§12 applicato. Da qui si procede con F1 (auth).

