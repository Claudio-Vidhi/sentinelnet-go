# Design — AI chat + generate-config endpoints (unit 2c-2)

Porta i due endpoint dell'AI Assistant di `routers/ai.py` (`/api/ai/chat`,
`/api/ai/generate-config`) verso il server Go. Consuma i context builder (2c-1)
e i profili (2b). Completa il port dell'AI Assistant.

## Obiettivo

Esporre a qualunque utente autenticato:

- `POST /api/ai/chat` — conversazione con il modello, con contesto opzionale
  allegato (inventario, running-config, tenant, FortiGate live, top flussi).
- `POST /api/ai/generate-config` — generazione della config di un nuovo switch
  da template o dai parametri comuni del tenant.

## Architettura

Un solo file nuovo: `internal/api/ai_chat_handlers.go` (metodi su `*App`). Due
rotte in `router.go` con `a.requireAuth("", …)` (qualunque utente autenticato,
come `get_current_user` in Python). Helper `activeProfile() *aiProfile` =
`findProfile(loadProfiles())`.

## Tipi di richiesta

Tag json speculari al Python:

```go
type aiChatMessage struct { Role, Content string }
type flowKeySchema struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	Protocol int    `json:"protocol"`
	DstPort  *int   `json:"dst_port"`
}
type aiChatReq struct {
	Messages          []aiChatMessage `json:"messages"`
	AttachInventory   bool            `json:"attach_inventory"`
	AttachDeviceIP    string          `json:"attach_device_ip"`
	AttachTenant      string          `json:"attach_tenant"`
	AttachFortigateIP string          `json:"attach_fortigate_ip"`
	AttachTopFlows    bool            `json:"attach_top_flows"`
	AttachFlowKeys    []flowKeySchema `json:"attach_flow_keys"`
	AttachDeviceIPs   []string        `json:"attach_device_ips"`
}
type aiGenerateConfigReq struct {
	Tenant     string `json:"tenant"`
	Hostname   string `json:"hostname"`
	MgmtIP     string `json:"mgmt_ip"`
	TemplateIP string `json:"template_ip"`
	Notes      string `json:"notes"`
}
```

## handleAIChat

1. `profile := a.activeProfile()`; nil → 400 "Nessun profilo AI
   configurato/attivo. Un amministratore deve crearne uno prima.".
2. `apiKey` = `vault.Decrypt(profile.APIKeyEnc)` se presente; se
   `provider != "ollama"` e `apiKey == ""` → 400 "API key non configurata per il
   profilo AI attivo.".
3. `messages` = payload messages → `[]ai.Message`.
4. `contextBlocks []string`, assemblati nell'ordine del Python. Ogni builder
   fallibile ritorna `(string, bool)`: su `!ok` ha già scritto la risposta →
   `return`.
   - `AttachInventory` → `deviceInventorySummary(scoped)` (puro).
   - `AttachDeviceIP != ""` → `deviceRunningConfigContext(w, r, ip)`.
   - `AttachDeviceIPs` → per ogni ip (cap 20), saltando quello == AttachDeviceIP,
     `deviceRunningConfigContext`.
   - `AttachTenant != ""` → `tenantContextBlock(w, r, tenant)`.
   - `AttachFortigateIP != ""` → `fortigateLiveContext(w, r, ip)`.
   - `AttachTopFlows || len(AttachFlowKeys) > 0` → `topFlowsContext(scoped, keys)`
     (puro). Se `len(AttachFlowKeys) > 20` → 400 "Troppi flussi selezionati:
     massimo 20 righe per analisi.". `keys` = mappa a `[]obsstore.FlowKey`;
     `scoped` = da `tenantsForUser`.
5. `instructionBlocks []string`: se `len(AttachDeviceIPs) > 0` e
   `roleAtLeast(claims.Role, "operator")` → il blocco-contratto di proposta
   config (testo verbatim dal Python, con il recinto ```sentinelnet-config```).
   Tenuto FUORI dal budget: non va mai troncato.
6. Se `len(contextBlocks) > 0 || len(instructionBlocks) > 0`:
   - `budget = ai.ContextCharBudget(provider, profile.Model, profile.ContextBudgetChars)`.
   - `question` = contenuto dell'ultimo messaggio con role "user" (""
     altrimenti).
   - `contextBlocks = ai.FitContext(contextBlocks, budget, question)`.
   - prepend un `ai.Message{Role:"system", Content: strings.Join(append(contextBlocks, instructionBlocks...), "\n\n")}`.
7. `ai.Chat(messages, ai.ChatOptions{Provider: provider, Model: profile.Model,
   APIKey: apiKey, BaseURL: profile.BaseURL, RateLimitRPM: &profile.RateLimitRPM,
   AllowUnredacted: profile.AllowUnredacted})`.
   - `*ai.RateLimitError` → 429; `*ai.Error` → 502.
8. Rispondi `{reply, provider, model: profile.Model || ai.GetDefaultModel(provider),
   profile_name: profile.Name}`.

## handleAIGenerateConfig

1. Stesso lookup profilo + decrypt + key check di handleAIChat.
2. `tenant`/`hostname` trim; se uno è vuoto → 400 "Tenant e hostname sono
   obbligatori.".
3. `if !a.assertGroupAllowed(w, r, tenant) { return }` (403 fuori scope, 404 se
   tenant sconosciuto).
4. `template_ip != ""` → `context, ok := deviceRunningConfigContext(w, r, template_ip)`
   (return su !ok); `source = "la running-config del dispositivo template {ip}"`.
   Altrimenti → `context, ok := tenantCommonParameters(w, r, tenant)` (return su
   !ok); `source = "i parametri comuni dell'ambiente del tenant"`.
5. Costruisci il prompt `question` (testo verbatim dal Python: righe hostname /
   IP mgmt / note, poi la richiesta di generazione con blocco unico).
6. `budget = ai.ContextCharBudget(provider, profile.Model, profile.ContextBudgetChars)`;
   `blocks = ai.FitContext([]string{context}, budget, question)`; messages =
   `{system: join(blocks)}` + `{user: question}`.
7. `ai.Chat(...)` come sopra; error mapping 429/502.
8. `auditLog("Config nuovo switch '{hostname}' (tenant '{tenant}') generata via
   AI dall'utente '{user}'.")`.
9. Rispondi `{reply, provider, model, profile_name}`.

## Testi verbatim (dal Python)

- Blocco istruzioni proposta config: il testo di `routers/ai.py` (funzione
  `ai_chat`, ramo `instruction_blocks.append(...)`), incluso il recinto
  ```sentinelnet-config``` e la clausola sui comandi distruttivi.
- Prompt di generate-config: il testo di `ai_generate_config` (`request_lines` +
  la `question` finale con "Genera la configurazione completa proposta…").

Questi testi sono riprodotti 1:1 nel piano di implementazione.

## Divergenze dal Python

Nessuna attesa. Il choke-point di redazione, il budget e la logica provider
sono già in `internal/ai`. `RateLimitRPM` è passato come `&profile.RateLimitRPM`
(il profilo contiene sempre un int; equivale al passaggio dell'int in Python).

## Test

`internal/api/ai_chat_handlers_test.go`, httptest contro gli handler con store/
obsstore/vault in-memory e un profilo attivo che punta a un endpoint **ollama**
httptest (nessuna chiave), così `ai.Chat` gira senza rete reale:

- nessun profilo attivo → 400.
- chat con `attach_inventory`: risposta 200 e la richiesta ricevuta dal fake
  server contiene il blocco inventario nel messaggio di sistema.
- `attach_flow_keys` con >20 elementi → 400.
- blocco proposta config presente solo per ruolo operator+ con
  `attach_device_ips` (assente per viewer).
- generate-config: tenant/hostname mancanti → 400; percorso template → risposta
  200.
- error mapping: fake server che risponde errore/429 → 502/429.

## Fuori scope

Nessuno: 2c-2 chiude l'AI Assistant. La UI (frontend) non fa parte del port.
