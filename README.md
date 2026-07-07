# SentinelNet (Go)

Port in Go dell'app SentinelNet (originale Python/FastAPI). Binario unico statico,
SQLite puro-Go (nessun CGO), frontend `dashboard.html` embeddato e servito as-is.

## Avvio

```bash
make run          # go run ./cmd/sentinelnet   → http://localhost:8000
make build        # binario statico ./sentinelnet
make test
```

All'avvio SentinelNet mostra una **finestra di dialogo nativa** (MessageBox su
Windows; zenity/terminale altrove) per scegliere come aprire l'interfaccia:

- **App integrata** — finestra dedicata senza barra indirizzi (Edge/Chrome in `--app`,
  profilo separato), aspetto di app nativa derivata dall'HTML.
- **Browser** — apre il browser predefinito.
- **Nessuna** — solo server, apri tu l'URL.

Salta la domanda con il flag `-ui` o l'env `SENTINELNET_UI` (`app` | `browser` | `none` | `ask`):

```bash
go run ./cmd/sentinelnet -ui app       # finestra dedicata
go run ./cmd/sentinelnet -ui browser   # browser predefinito
go run ./cmd/sentinelnet -ui none      # nessuna apertura (deploy/headless)
```

**Arresto automatico**: con interfaccia attiva (app o browser), il server si arresta
e **libera la porta** alla chiusura dell'interfaccia — quando la finestra app dedicata
si chiude, o quando la pagina smette di inviare heartbeat (scheda/finestra chiusa).
Con `-ui none` questo comportamento è disattivo (deployment come servizio).

Prima esecuzione: nella pagina il wizard crea il primo admin.

## Configurazione (variabili d'ambiente)

| Variabile | Default | Descrizione |
|---|---|---|
| `SENTINELNET_ADDR` | `:8000` | indirizzo di ascolto HTTP |
| `SENTINELNET_DATA_DIR` | `data` | DB SQLite, chiavi, `backup-config/`, `audit.log` |
| `SENTINELNET_JWT_SECRET` | (auto) | segreto JWT; se vuoto è generato e persistito |
| `SENTINELNET_MASTER_KEY` | (auto) | chiave AES-256 base64 (32 byte) per le password apparato |
| `SENTINELNET_DEFAULT_USER` / `_PASS` / `_SECRET` | — | credenziali del "Profilo Rete Standard" (device con `profile=default`) |
| `SENTINELNET_HOST` / `SENTINELNET_PORT` | — | override host/porta; senza override vale il bind IP salvato da `/api/settings/network` |
| `SENTINELNET_UI` | `ask` | interfaccia all'avvio: `app` \| `browser` \| `none` \| `ask` (sovrascrivibile con `-ui`) |

## Struttura

```
cmd/sentinelnet/       entrypoint + graceful shutdown
internal/config/       env
internal/store/        SQLite (WAL) + migrazioni embed; users, inventory, classify, mac, topology
internal/auth/         JWT HS256, bcrypt, lockout, OTP WebSocket
internal/crypto/       vault AES-GCM + master key
internal/collect/      SSH/CLI (Netmiko-lite): triage, backup, comandi, ping, terminale interattivo
internal/topology/     parser CDP/LLDP, port-channel, VTP
internal/mac/           parser MAC address-table / bridge-domain
internal/euvd/          proxy ENISA EUVD (whitelist param, size ≤ 100)
internal/configanalyzer/ analisi running-config dai backup (interfacce, VLAN, ACL, rotte, VPN)
internal/ui/            avvio interfaccia: finestra app (Chromium --app) o browser
internal/api/           router chi, middleware RBAC/tenant scoping, handler (contratti JSON = FastAPI)
web/                    dashboard.html (embed.FS) — copia servita dal binario
```

Le rotte `/api/...` mantengono i contratti JSON dell'app FastAPI: il frontend gira invariato.

## Note

- `collect.Ping` usa un probe TCP sulla porta 22 (niente ICMP raw / privilegi elevati).
- Il terminale CLI usa una WS autenticata con OTP monouso a 30s (endpoint `/api/ws-token`).
- I backup config sono file in `data/backup-config/<tenant>/<host>-<ip>.txt`.
- Trasporti MAC NETCONF/RESTCONF: attualmente il MAC scan usa CLI (con override ad-hoc
  per apparati non standard, es. bridge-domain su C8000V).
- **Origine MAC**: ogni avvistamento è marcato *accesso* (porta dove il device è
  collegato) o *transito* (visto su un uplink verso un vicino). L'uplink è dedotto
  dalla topologia CDP/LLDP e dai port-channel. `GET /api/mac/locate?mac=...` e il
  pulsante "localizza" in MAC Tracker mostrano origine e switch di transito.
- **UI**: il file servito è `web/dashboard.html` (embeddato nel binario).
