# Design — AI Provider Core (`internal/ai`)

Data: 2026-07-21 · Sub-unità **2a** di 3 dell'AI Assistant (unità 2 di "MCP + AI").
Le altre sub-unità: **2b** profili + rotte `/api/ai/models`, **2c** chat +
generate-config + context builder. Ciascuna con spec/plan/implementazione propri.

## Obiettivo

Portare `ai/ai_assistant.py` (586 righe) in un package Go `internal/ai`: la
libreria di astrazione verso i provider LLM. **Nessuna rotta HTTP** — è la
fondazione che 2b e 2c chiamano. Comportamento 1:1 col Python, salvo l'unica
divergenza dichiarata (§ divergenza).

Espone: una `Chat(...)` sincrona verso 4 provider (Anthropic, OpenAI, Gemini,
Ollama) via HTTP grezzo; `ListModels`; la logica di budget/adattamento del
contesto; un rate limiter a finestra scorrevole; il formatter del contesto
tenant; e il **choke-point di redazione** (finding I-1) prima che qualunque
contenuto lasci il processo.

## Vincoli invarianti

1. **Choke-point di redazione (I-1)**: in `Chat`, il contenuto di ogni messaggio
   passa per `redact.Text` PRIMA di raggiungere qualunque provider, **tranne**
   quando `AllowUnredacted && isLocal`. `isLocal = provider=="ollama" ||
   (provider=="openai" && IsLocalBaseURL(baseURL))`. Fail-closed per tutto il
   resto: se non si è certi che sia locale e autorizzato, si redige.
2. **Nessun SDK di provider**: solo `net/http` + `encoding/json` (come il
   `requests` del Python). Nessuna dipendenza nuova.
3. **Solo stdlib + `internal/redact`**: `internal/ai` non importa `internal/api`
   né altri package applicativi. È una libreria foglia.
4. **1:1 col Python** su URL, header, forma dei payload, parsing delle risposte,
   budget per-modello e logica di `fit_context` — salvo la divergenza §.

## Architettura

```
internal/ai/
    chat.go       Chat(msgs []Message, opts ChatOptions) (string, error):
                  redazione -> rate limit -> dispatch al provider.
                  Message, ChatOptions, Error, RateLimitError, splitSystem.
    providers.go  chatAnthropic / chatOpenAI / chatGemini / chatOllama:
                  costruzione richiesta HTTP grezza + parsing risposta;
                  providerHTTPError (429 -> RateLimitError).
    models.go     ListModels + lister per provider; DEFAULT_MODELS;
                  GetDefaultModel; normalizeGeminiModel; filtro non-chat OpenAI.
    context.go    ContextCharBudget, FitContext, filterRelevantSections,
                  truncateHeadTail, questionKeywords, BuildTenantContext.
    ratelimit.go  RateLimiter (finestra scorrevole, mutex) + limiter di
                  package + ConfigureRateLimit.
    local.go      IsLocalBaseURL (loopback / RFC1918).
```

### API pubblica (consumata da 2b/2c)

```go
type Message struct { Role, Content string }

type ChatOptions struct {
    Provider        string        // anthropic | openai | gemini | ollama
    Model           string        // "" = default per provider
    APIKey          string        // richiesta per anthropic/openai/gemini
    BaseURL         string        // override (ollama; openai-compatibili)
    Timeout         time.Duration // 0 = default 60s
    RateLimitRPM    int           // <=0 = illimitato; riconfigura il limiter
    AllowUnredacted bool          // salto redazione: solo LLM locali fidati
}

func Chat(msgs []Message, opts ChatOptions) (string, error)
func ListModels(provider, apiKey, baseURL string) ([]string, error)
func GetDefaultModel(provider string) string
func ContextCharBudget(provider, model string, override int) int
func FitContext(blocks []string, budget int, question string) []string
func BuildTenantContext(args TenantContextArgs) string
func ConfigureRateLimit(rpm int)
func IsLocalBaseURL(baseURL string) bool

// Errori tipizzati (errors.As):
type Error struct{ ... }          // AiAssistantError
type RateLimitError struct{ ... } // RateLimitExceededError (sottotipo logico)
```

`ChatOptions` sostituisce i parametri keyword del Python `chat(...)` — stessi
campi, stesso comportamento. `TenantContextArgs` raggruppa i parametri di
`build_tenant_context` (tenant, devices, group_info, site, mac_stats,
mac_recent, scan_summary, max_devices, max_recent).

## Parità di comportamento

- **Redazione**: per ogni messaggio, `content = redact.Text(content)` salvo
  `AllowUnredacted && isLocal` (vedi vincolo 1). Unico punto di uscita.
- **Provider (esatti come il Python)**:
  - Anthropic: `POST https://api.anthropic.com/v1/messages`, header `x-api-key`,
    `anthropic-version: 2023-06-01`, `max_tokens: 2048`, sistema separato in
    `system`, messaggi non-system in `messages`. Risposta: concat dei blocchi
    `type=="text"`.
  - OpenAI: `POST {base_url|https://api.openai.com/v1}/chat/completions`, header
    `Authorization: Bearer`, messaggi passati com'è. Risposta:
    `choices[0].message.content`.
  - Gemini: `POST .../v1beta/models/{model}:generateContent?key=`, ruolo
    `assistant->model`, `systemInstruction` per il sistema. Nome modello
    normalizzato togliendo il prefisso `models/`. Risposta: concat dei `parts`.
  - Ollama: `POST {base_url|http://localhost:11434}/api/chat`, `stream:false`.
    Risposta: `message.content`.
  - Errore provider `429` -> `RateLimitError` con messaggio localizzato (quota
    provider); altri `>=400` -> `Error` con `<Provider> API error <code>: <body>`.
- **ListModels**: Gemini `GET .../models?key=` filtrato a chi supporta
  `generateContent` (nome normalizzato); OpenAI `GET {base}/models` meno gli
  hint non-chat (`embedding, whisper, tts, dall-e, moderation, davinci-002,
  babbage-002, text-, audio, realtime, transcribe, image`), ordinato; Anthropic
  `GET /v1/models`; Ollama `GET {base}/api/tags`.
- **Budget contesto**: `ContextCharBudget` — override>0 vince; altrimenti per
  nome modello: `gemma`->24000; contiene `-lite`/`-mini`/`haiku`/`nano`->100000;
  provider `ollama`->48000; altrimenti 200000. `FitContext`: se il totale supera
  il budget, riduce ogni blocco in proporzione (minimo 400), filtrando i blocchi
  grandi per sezioni pertinenti alle parole chiave della domanda
  (`filterRelevantSections`), poi troncamento testa+coda con marcatore
  `\n... [contesto troncato] ...\n`.
- **Rate limiter**: finestra scorrevole di 60s, thread-safe (mutex); limiter di
  package condiviso, riconfigurato a ogni `Chat` se `RateLimitRPM` è indicato
  (>0). Oltre il limite -> `RateLimitError`. `rpm<=0` = illimitato.
- **`GetDefaultModel`**: minuscolo, `""` se provider ignoto.

## Divergenza (§ documentata in DIVERGENZE §13)

`DEFAULT_MODELS` — il default Anthropic passa da `claude-3-5-sonnet-latest`
(Python) a **`claude-sonnet-5`** (modello corrente 2026). openai
(`gpt-4o-mini`), gemini (`gemini-3-flash`), ollama (`llama3`) restano verbatim.
Il default si applica SOLO quando un profilo non imposta un modello; l'utente
può sempre sovrascriverlo. Motivo: l'alias Python è datato e potrebbe non
risolvere più, causando il fallimento della prima chat di un profilo senza
modello.

## Testing (golden dal Python + httptest)

1. **Golden** (generati eseguendo il Python, confronto normalizzato):
   `ContextCharBudget` (tabella provider/modello/override), `FitContext` su
   blocchi campione (con e senza superamento budget, con domanda), `truncateHeadTail`,
   `BuildTenantContext` su input campione.
2. **Costruzione richiesta provider** (httptest): un server fittizio per
   provider — si asserisce metodo, URL, header, payload della richiesta uscente;
   si ritorna una risposta preconfezionata e si asserisce il testo/elenco
   modelli estratto. Un test **end-to-end di redazione**: un segreto in un
   messaggio deve risultare mascherato quando raggiunge il provider (non locale)
   fittizio.
3. **Unit**: rate limiter (`rpm=2` -> la terza chiamata entro 60s è bloccata),
   `IsLocalBaseURL` (localhost/loopback/RFC1918 true; pubblico false),
   `normalizeGeminiModel`, `splitSystem`, `GetDefaultModel`, mapping `429 ->
   RateLimitError`.

Ogni golden va provato a fallire con una mutazione prima di fidarsi del verde.

## Confine di scope

- **Solo libreria.** Nessuna rotta, nessun accesso a store/vault/inventario. La
  cifratura delle chiavi, i profili e l'assemblaggio del contesto stanno in 2b
  e 2c.
- `BuildTenantContext` è **solo il formatter** (come nel Python): riceve dati
  già filtrati per tenant, non li recupera. Il recupero/scoping è di 2c.

## Fuori scope (sub-unità successive)

- **2b**: profili AI CRUD (`/api/ai/profiles*`) con chiavi cifrate dal vault +
  mascheratura, e `/api/ai/models`.
- **2c**: `/api/ai/chat`, `/api/ai/generate-config`, e i sei context builder.
