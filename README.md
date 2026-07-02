# SentinelNet (Go)

Port in Go dell'app SentinelNet (originale Python/FastAPI). Binario unico statico,
SQLite puro-Go (nessun CGO), frontend `dashboard.html` embeddato e servito as-is.

## Avvio

```bash
make run          # go run ./cmd/sentinelnet   → http://localhost:8000
make build        # binario statico ./sentinelnet
make test
```

Prima esecuzione: apri `http://localhost:8000`, il wizard crea il primo admin.

## Configurazione (variabili d'ambiente)

| Variabile | Default | Descrizione |
|---|---|---|
| `SENTINELNET_ADDR` | `:8000` | indirizzo di ascolto HTTP |
| `SENTINELNET_DATA_DIR` | `data` | DB SQLite, chiavi, `backup-config/`, `audit.log` |
| `SENTINELNET_JWT_SECRET` | (auto) | segreto JWT; se vuoto è generato e persistito |
| `SENTINELNET_MASTER_KEY` | (auto) | chiave AES-256 base64 (32 byte) per le password apparato |
| `SENTINELNET_DEFAULT_USER` / `_PASS` / `_SECRET` | — | credenziali del "Profilo Rete Standard" (device con `profile=default`) |

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
internal/api/           router chi, middleware RBAC/tenant scoping, handler (contratti JSON = FastAPI)
web/                    dashboard.html (embed.FS)
```

Le rotte `/api/...` mantengono i contratti JSON dell'app FastAPI: il frontend gira invariato.

## Note

- `collect.Ping` usa un probe TCP sulla porta 22 (niente ICMP raw / privilegi elevati).
- Il terminale CLI usa una WS autenticata con OTP monouso a 30s (endpoint `/api/ws-token`).
- I backup config sono file in `data/backup-config/<tenant>/<host>-<ip>.txt`.
- Trasporti MAC NETCONF/RESTCONF: attualmente il MAC scan usa CLI (con override ad-hoc
  per apparati non standard, es. bridge-domain su C8000V).
