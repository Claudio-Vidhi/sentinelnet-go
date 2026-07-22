# Design — Identity Manager (Credential Profiles)

Porta il modulo `security/identity_manager.py` dall'app Python verso il server Go.
Consente di creare profili credenziali riusabili per tenant, a cui i dispositivi in inventario possono fare riferimento tramite il valore `identity:<id>` nel campo `Profile`.

## Obiettivo

- Memorizzare in SQLite (`identities` table) i profili credenziali nominati per tenant.
- Cifrare `password_enc` e `secret_enc` tramite `crypto.Vault` (AES-GCM). Le API di lettura non espongono MAI i segreti in chiaro.
- Esporre le rotte CRUD `/api/identities` con scoping per tenant (`assertGroupAllowed` / `tenantsForUser`).
- Fornire la risoluzione interna `GetIdentityCredentials(id)` per le connessioni SSH/CLI agli apparati che usano `identity:<id>`.

## Schema Database (`internal/store/migrations/0011_identities.sql`)

```sql
CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    tenant TEXT NOT NULL,
    username TEXT NOT NULL,
    password_enc TEXT NOT NULL DEFAULT '',
    secret_enc TEXT NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_identities_tenant ON identities(tenant);
```

## Tipi Go (`internal/store/identities.go`)

```go
type Identity struct {
    ID           string `json:"id"`
    Name         string `json:"name"`
    Tenant       string `json:"tenant"`
    Username     string `json:"username"`
    PasswordEnc  string `json:"-"`
    SecretEnc    string `json:"-"`
    DevicesUsing int    `json:"devices_using"`
}

type IdentityCredentials struct {
    Username string
    Password string
    Secret   string
}
```

## API Rotte (`internal/api/identity_handlers.go`)

- `GET /api/identities` (autenticato, scope tenant) -> `{ "identities": [...] }`
- `POST /api/identities` (operator+, scope tenant) -> `{ "status": "success", "identity": {...} }`
- `PUT /api/identities/{id}` (operator+, scope tenant) -> `{ "status": "success" }`
- `DELETE /api/identities/{id}` (operator+, scope tenant) -> `{ "status": "success" }` (409 se in uso da almeno un device)

## Contratto Risposte & Errore

- Le risposte non contengono mai `password_enc` o `secret_enc`.
- Se si tenta di eliminare un'identità associata a dispositivi, risponde `409 Conflict` con `{ "detail": "Impossibile eliminare: l'identità è in uso da N dispositivi.", "devices": ["10.0.0.1", ...] }`.
