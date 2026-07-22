# Design — MCP Client (Preview) Endpoints

Porta il router `routers/mcp_client.py` dall'app Python verso il server Go (`internal/api/mcp_client_handlers.go`).

## Obiettivo

SentinelNet come **CLIENT MCP** verso server esterni (Jira, ServiceNow, ecc. via HTTP Streamable/JSON-RPC 2.0).

- **Gating**: Le chiamate live (`/tools` e `/call`) sono gated dal flag `mcp_preview_enabled` (403 se disabilitato).
- **RBAC**: Solo `admin` (rispecchia la RBAC del pannello MCP).
- **Storage**: Salva le impostazioni via `store.SetSetting` / `store.GetSetting` per `mcp_preview_enabled` (bool) e `mcp_client_servers` (JSON array di `{name, url, auth_enc}`).
- **Cifratura**: I token di autenticazione dei server sono cifrati tramite `crypto.Vault` (`auth_enc`) e mai restituiti in chiaro al frontend.

## Rotte (`internal/api/mcp_client_handlers.go`)

- `GET /api/mcp-client/settings` (admin) -> `{ "preview_enabled": bool, "servers": [...] }`
- `POST /api/mcp-client/preview` (admin) -> `{ "status": "success", "preview_enabled": bool }`
- `GET /api/mcp-client/servers` (admin) -> `{ "servers": [...] }`
- `POST /api/mcp-client/servers` (admin) -> `{ "status": "success", "server": {...} }`
- `DELETE /api/mcp-client/servers/{name}` (admin) -> `{ "status": "success" }`
- `GET /api/mcp-client/{name}/tools` (admin, gated) -> `{ "tools": [...] }`
- `POST /api/mcp-client/{name}/call` (admin, gated) -> `{ "result": ... }`
