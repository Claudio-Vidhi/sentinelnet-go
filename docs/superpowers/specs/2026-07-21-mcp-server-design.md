# Design — MCP Server (port Go)

Data: 2026-07-21 · Unità 1 di 3 del dominio "MCP + AI" (le altre: AI Assistant,
MCP Client-preview, ciascuna con spec/plan/implementazione propri).

## Obiettivo

Portare `ai/mcp_server.py` (server MCP su stdio) e `routers/mcp.py` (3 rotte di
amministrazione) nel port Go, mantenendo il comportamento 1:1 con il Python.

Il server MCP espone SentinelNet come server Model Context Protocol su stdio,
così un client LLM esterno (Claude Desktop, Cline, LM Studio, ecc.) può
interrogare inventario, mappa di rete, MAC/ARP, config analyzer, FortiGate, WLC,
provisioning e osservabilità, ed eseguire comandi CLI. **Non reimplementa alcuna
logica**: è un ponte autenticato verso l'API REST del centrale. Autorizzazione
(ruoli, tenant, blacklist comandi) resta interamente lato server.

## Vincoli invarianti

1. **Contratto verso i client LLM**: nomi tool, descrizioni (in inglese, sono il
   prompt che l'LLM legge) e `inputSchema` devono restare identici al Python.
   Verificato byte-per-byte con golden.
2. **Choke-point di redazione (finding I-1)**: ogni risultato che torna a un
   client LLM passa per `internal/redact` prima di lasciare il processo, come in
   Python (`redact(r.json())`).
3. **Nessuna logica duplicata**: le decisioni di autorizzazione restano nell'API
   REST. Il server MCP inoltra e basta.
4. **Contratto `/api/mcp/*`**: le 3 rotte restano field-compatibili (il processo
   MCP legge `/api/mcp/tool-config`; una futura UI usa `/api/mcp/settings`).

## Packaging

Sottocomando del binario esistente: **`sentinelnet mcp`** (scelta utente). Un
solo artefatto statico da distribuire e versionare. La configurazione del client
LLM cambia solo `command`/`args`:

```json
{"mcpServers": {"sentinelnet": {
    "command": "sentinelnet.exe", "args": ["mcp"],
    "env": {"SENTINELNET_URL": "http://127.0.0.1:8765",
            "SENTINELNET_USERNAME": "admin", "SENTINELNET_PASSWORD": "..."}}}}
```

Variabili d'ambiente lette (identiche al Python):
`SENTINELNET_URL` (default `http://127.0.0.1:8765`), `SENTINELNET_USERNAME`,
`SENTINELNET_PASSWORD`, `SENTINELNET_VERIFY_TLS` (`"0"` per non verificare TLS).
Senza username/password il sottocomando scrive su stderr ed esce con codice 1.

## Architettura

```
cmd/sentinelnet/main.go
    if len(os.Args) > 1 && os.Args[1] == "mcp":  mcp.Serve(ctx, stdin, stdout); return
    else:                                         avvio server invariato

internal/mcp/
    registry.go    ~40 tool come dati: Tool{Name, Description, InputSchema, BuildRequest}
    server.go      loop JSON-RPC su stdio: initialize / notifications/initialized /
                   ping / tools/list / tools/call / method-not-found
    client.go      HTTP client da env: login, JWT Bearer, retry 1x su 401, redazione
    toolconfig.go  poll di /api/mcp/tool-config con cache TTL 60s

internal/api/mcp_handlers.go
    GET  /api/mcp/settings      (admin) catalogo tool + disabled_tools
    POST /api/mcp/settings      (admin) imposta disabled_tools (valida, audit)
    GET  /api/mcp/tool-config   (auth)  { "disabled_tools": [...] } — letto dal processo MCP
```

`mcp.Serve` non tocca DB, vault o store: è un client HTTP puro. La separazione in
package `internal/mcp` (invece che dentro `cmd/`) serve a rendere il registry e
il mapping richieste testabili offline.

### Modello del tool

Un tool è un dato, non una closure opaca:

```go
type Tool struct {
    Name        string
    Description string          // inglese, verbatim dal Python (contratto LLM)
    InputSchema map[string]any  // JSON Schema, come _obj(...) del Python
    BuildRequest func(args map[string]any) Request
}
type Request struct {
    Method string            // GET | POST
    Path   string            // es. "/api/fortigate/10.0.0.1/status"
    Query  map[string]string // querystring (nil se assente)
    Body   any               // corpo JSON (nil se assente)
}
```

`BuildRequest` è la porta delle lambda Python (`lambda a: api(method, path,
params=, body=)`). Essendo una funzione pura, è golden-testabile senza rete.

## Parità di comportamento

- **Tabella tool 1:1** — stessi ~40 nomi/descrizioni/schemi e stesso mapping
  verso endpoint. Tutte le rotte di destinazione esistono già nel server Go
  (verificato: local-devices, network-map, portchannels, mac/*, arp/*,
  config-analyzer, triage-status, send-command, sites, fortigate/*, wlc/*,
  provisioner/{generate,fgt/generate}, observability/{top,anomalies}).
- **Redazione risultato** — `internal/redact` su ogni risultato API; su risposta
  non-JSON si redige il testo. Poi troncamento a 200 000 caratteri con marcatore
  `\n... [truncated]`.
- **Auth** — login pigro alla prima chiamata; header `Authorization: Bearer
  <jwt>`; su `401` alla prima prova si rifà login e si riprova una volta; HTTP
  ≥400 → risultato tool con `isError: true` e messaggio `HTTP <code>: <detail>`.
- **tools/call** — tool sconosciuto o disabilitato → `isError` con messaggio;
  eccezione durante la chiamata → `isError` con `Error: <err>`.
- **Rotte `/api/mcp/*`** — `disabled_tools` salvato come lista JSON sotto una
  singola chiave di setting (`store.SetSetting`/`GetSetting`), equivalente a
  `app_settings["mcp"]["disabled_tools"]` del Python. Default (nessuna config
  salvata): `{get_top_talkers, get_anomalies}` intersecato coi tool noti. POST
  rifiuta nomi sconosciuti con 400 e scrive un audit log; GET settings ritorna
  `{tools:[{name,description}], disabled_tools:[...]}`; tool-config ritorna
  `{disabled_tools:[...]}`.
- **Cache disabled-tools nel processo MCP** — `tools/list` e `tools/call`
  filtrano i tool disabilitati; il set è letto da `/api/mcp/tool-config` con TTL
  60s (su errore si tiene l'ultimo noto), come il Python.

### Protocollo JSON-RPC (stdio)

Un messaggio JSON per riga su stdin/stdout. Metodi gestiti:

- `initialize` → `{protocolVersion, capabilities:{tools:{}}, serverInfo}`
  (`protocolVersion` riecheggiato dalla richiesta, default `2025-06-18`;
  `serverInfo = {name:"sentinelnet", version:"1.0.0"}`).
- `notifications/initialized` → nessuna risposta (è una notifica).
- `ping` → `{}`.
- `tools/list` → `{tools:[{name, description, inputSchema}]}` esclusi i disabilitati.
- `tools/call` → `{content:[{type:"text", text:<json|string>}]}` o `isError`.
- Altri metodi con `id` → errore JSON-RPC `-32601` "Method not found".
  Righe vuote o JSON non valido → ignorate.

## Testing (golden offline, generati dal Python)

1. **Golden `tools/list`** — l'output del registry vs. il `tools/list` del Python,
   byte-per-byte (nomi, descrizioni, `inputSchema`). Generato eseguendo il modulo
   Python; mai scritto a mano.
2. **Golden mapping richieste** — per ogni tool, dati argomenti campione, la
   `Request{Method,Path,Query,Body}` prodotta. Il golden si genera dal Python
   stubbando `api()` per registrare `(method, path, params, body)` per ogni tool.
   Prova che il ponte argomenti→richiesta è identico, senza rete.
3. **Unit** — framing JSON-RPC (initialize/ping/method-not-found), rifiuto tool
   disabilitato, redazione applicata, troncamento a 200k, eccezione→`isError`.
4. **Handler `/api/mcp`** — round-trip GET/POST settings, 400 su tool
   sconosciuto, set di default, presenza dell'audit log.

Ogni golden va provato "a fallire" con una mutazione prima di fidarsi del verde.

## Confine di scope e divergenze

- **Solo backend.** Il tab admin "MCP Server" (UI di abilita/disabilita tool)
  resta nel workstream della dashboard rinviato, come gli altri gap UI. Il
  contratto `/api/mcp/settings` è rispettato perché una futura UI ci si innesti.
- **Divergenza (nota doc)**: invocazione `sentinelnet mcp` invece dello script
  separato `mcp_server.py` del Python — conseguenza della scelta di packaging.
  Da annotare in `docs/DIVERGENZE-DAL-PYTHON.md`. Tutto il resto è 1:1.

## Fuori scope (unità successive)

- **AI Assistant** (`ai/ai_assistant.py`, `routers/ai.py`) — unità 2.
- **MCP Client-preview** (`ai/mcp_client.py`, `routers/mcp_client.py`) — unità 3.
