# Design — AI profile CRUD + models route (unit 2b)

Porta di `routers/ai.py` (parte profili/modelli) verso il server Go. Copre la
gestione dei profili di connessione AI e l'elenco dei modelli. La chat, la
generazione config e i context builder sono l'unità 2c, **fuori** da questo spec.

## Obiettivo

Esporre, solo per admin, gli endpoint CRUD dei profili AI e l'elenco modelli:

- `GET    /api/ai/profiles`
- `POST   /api/ai/profiles`
- `PUT    /api/ai/profiles/{id}`
- `DELETE /api/ai/profiles/{id}`
- `POST   /api/ai/profiles/{id}/activate`
- `GET    /api/ai/models?provider=&profile_id=`

Le chiavi API sono cifrate a riposo con il `crypto.Vault` esistente e non sono
mai esposte in chiaro via API.

## Architettura

Un solo file nuovo: `internal/api/ai_handlers.go`. Nessun package nuovo,
nessuna migrazione SQL. I profili sono persistiti come JSON nella tabella
`settings` (KV) già usata dal server:

- `settings["ai_profiles"]`       → stringa JSON, array di profili
- `settings["ai_active_profile"]` → id del profilo attivo (stringa vuota = nessuno)

Le rotte sono registrate in `router.go` con `a.requireAuth("admin", …)`, come
`require_admin` in Python su ogni endpoint profili/modelli.

## Dati

Struct interna `aiProfile` con tag json speculari al dict Python:

```go
type aiProfile struct {
    ID                 string `json:"id"`
    Name               string `json:"name"`
    Provider           string `json:"provider"`
    Model              string `json:"model"`
    BaseURL            string `json:"base_url"`
    APIKeyEnc          string `json:"api_key_enc"`
    RateLimitRPM       int    `json:"rate_limit_rpm"`
    AllowUnredacted    bool   `json:"allow_unredacted"`
    ContextBudgetChars int    `json:"context_budget_chars"`
}
```

Helper:

- `loadProfiles() ([]aiProfile, string)` — legge/deserializza le due chiavi
  settings; lista vuota + attivo "" se assenti. Nessuna migrazione legacy (vedi
  Divergenze).
- `saveProfiles(list []aiProfile, active string) error` — serializza e scrive
  entrambe le chiavi.
- `findProfile(list, id) *aiProfile` — nil se id vuoto o non trovato.
- `maskProfile(p) map[string]any` — rappresentazione sicura: **mai**
  `api_key_enc`; espone `api_key_set bool = api_key_enc != ""`. Campi:
  `id,name,provider,model,base_url,api_key_set,rate_limit_rpm,allow_unredacted,context_budget_chars`.

`_AI_PROVIDERS` → set `{"anthropic","openai","gemini","ollama"}`.

## Endpoint

Tutti admin. Corpo di risposta identico al Python.

### GET /api/ai/profiles
`{ "profiles": [masked...], "active_profile": <id|""> }`.

### POST /api/ai/profiles
Corpo: `name, provider, model, api_key, base_url, rate_limit_rpm,
allow_unredacted, context_budget_chars`.

- `provider` normalizzato a lower+trim; se ∉ `_AI_PROVIDERS` → 400.
- `name` trim non vuoto, altrimenti → 400.
- `assertUnredactedAllowed(allow_unredacted, provider, base_url)` → 400 se viola.
- `api_key_enc` = `vault.Encrypt(api_key)` se `api_key` non vuota, altrimenti "".
- `rate_limit_rpm` e `context_budget_chars` = `max(0, v)`.
- id = 32 hex casuali (equivalente `uuid4().hex`).
- append; se non c'è attivo, il nuovo diventa attivo.
- audit log; risponde `maskProfile(new)`.

### PUT /api/ai/profiles/{id}
Aggiornamento parziale. Il corpo usa **puntatori** (`*string/*int/*bool`) per
distinguere campo assente da `null` da valore. Semantica Python 1:1:

- `name` (se presente): trim non vuoto o 400.
- `provider` (se presente): validato contro `_AI_PROVIDERS` o 400.
- `model`, `base_url` (se presenti): trim.
- `rate_limit_rpm`, `context_budget_chars` (se presenti): `max(0, v)`.
- `api_key`: **assente/`null`** → mantiene la chiave salvata; **`""`** → la
  rimuove; **valore** → cifra e sostituisce.
- `allow_unredacted` (se presente): assegna.
- Dopo gli assegnamenti, riesegue `assertUnredactedAllowed` sul profilo
  risultante (difesa in profondità).
- salva; audit; risponde `maskProfile(profile)`. 404 se id non trovato.

### DELETE /api/ai/profiles/{id}
Rimuove il profilo. Se era l'attivo, l'attivo diventa il primo rimanente (o ""
se lista vuota). 404 se non trovato. Risponde `{"status":"success"}`.

### POST /api/ai/profiles/{id}/activate
Imposta l'attivo su `{id}`. 404 se non trovato. Risponde
`{"status":"success","active_profile":<id>}`.

### GET /api/ai/models
Query: `provider` e `profile_id` opzionali. Risolve il profilo:

1. `findProfile(profile_id)` se dato, altrimenti il profilo attivo.
2. `prov` = `provider` della query, altrimenti quello del profilo (lower+trim).
   Vuoto → 400 "Nessun provider AI configurato.".
3. Se il profilo risolto usa un provider diverso da `prov`, cerca un altro
   profilo il cui provider == `prov` e che abbia una chiave (o sia `ollama`);
   se esiste lo usa (per validare un provider prima di salvarlo).
4. `api_key` = `vault.Decrypt(profile.APIKeyEnc)` se presente, altrimenti "".
5. `base_url` = `profile.BaseURL` (o "").
6. `ai.ListModels(prov, api_key, base_url)`; `*ai.Error` → 502.
7. Risponde `{ "provider": prov, "models": [...], "default_model":
   ai.GetDefaultModel(prov) }`.

## Gate non-redatto

```go
func (a *App) assertUnredactedAllowed(allow bool, provider, baseURL string) error
```

Se `!allow` → ok. Altrimenti ok solo se `provider=="ollama"` oppure
(`provider=="openai"` e `ai.IsLocalBaseURL(baseURL)`). Altrimenti errore 400 con
lo stesso messaggio del Python (invio config non redatte consentito solo verso
LLM locali). Usato in create e update.

## Divergenze dal Python (→ DIVERGENZE-DAL-PYTHON.md §14)

1. **Nessuna migrazione legacy.** Python migra il vecchio dict singolo `ai` in
   `ai_profiles` alla prima lettura. Il port Go non ha dati storici in quel
   formato: `loadProfiles` parte da lista vuota quando le chiavi mancano.
2. `rate_limit_rpm` persistito come int semplice (0 = nessun limite). Il tipo
   `*int` per distinguere None da 0 riguarda solo il passaggio a `chat()`
   (unità 2c), non lo storage del profilo.

## Test

`internal/api/ai_handlers_test.go`, httptest sul router reale con store
in-memory + vault. Specchio di `test_app_server_ai_profiles.py` più activate e
validazione:

- profili vuoti all'inizio (`profiles: []`, `active_profile: ""`).
- `maskProfile` non espone mai la chiave in chiaro né `api_key_enc`;
  `api_key_set` riflette la presenza.
- create → update → delete roundtrip, con verifica della semantica `api_key`
  (assente mantiene, `""` rimuove, valore sostituisce).
- activate imposta `active_profile`; delete dell'attivo ripiega sul primo.
- provider non valido → 400; nome vuoto → 400; gate non-redatto su provider
  remoto → 400.
- `GET /api/ai/models` contro un endpoint ollama httptest (nessuna chiave) per
  esercitare la risoluzione del profilo senza rete reale.

## Fuori scope (unità 2c)

`/api/ai/chat`, `/api/ai/generate-config` e i sei context builder
(`_device_inventory_summary`, `_device_running_config_context`,
`_fortigate_live_context`, `_tenant_context_block`, `_tenant_common_parameters`,
top-flows).
