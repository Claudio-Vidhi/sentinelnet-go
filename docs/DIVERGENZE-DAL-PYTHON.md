# Divergenze deliberate dall'app Python

Il port Go riproduce la **logica di alto livello** dell'app Python, non il suo
codice riga per riga. Dove il Python ha un comportamento chiaramente anomalo,
il Go fa la cosa corretta e la differenza viene annotata qui, invece di
propagare la stranezza.

Questo file è la fonte di verità per "perché il Go si comporta diversamente":
se una differenza non è elencata qui, è un bug, non una scelta.

---

## 1. Filtro dei MAC broadcast nella tabella ARP

**Python** (`collectors/arp_collector.py`, `parse_arp_output`):

```python
if mac.lower().replace('-', ':').replace('.', '') in ("ffffffffffff", "000000000000"):
    continue
```

La sostituzione `'-'` → `':'` lascia i due punti nella stringa, quindi il
confronto riesce **solo** per la forma puntata `ffff.ffff.ffff`. Le forme
`ff:ff:ff:ff:ff:ff` e `ff-ff-ff-ff-ff-ff` superano il filtro e finiscono in
`arp_entries` come se fossero client reali.

**Go**: si rimuovono tutti i separatori prima del confronto, quindi il
broadcast viene scartato in qualunque notazione.

**Effetto**: il Go scrive qualche riga spazzatura in meno. Nessun impatto sui
dati legittimi.

---

## 2. Formati MAC di HP/ProCurve non riconosciuti

**Python**: la regex dei MAC in `arp_collector.py` copre solo

- sei gruppi da due cifre (`aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`)
- tre gruppi da quattro puntati (`aabb.ccdd.eeff`)

Gli apparati HP/ProCurve stampano `001a4b-2c3d4e` (6-6) e `001a-4b2c-3d4e`
(4-4-4), che **non corrispondono**: le righe ARP di quegli switch vengono
silenziosamente ignorate.

**Go**: la regex accetta anche le due forme HP.

**Effetto**: la raccolta ARP funziona anche sugli switch HP, che con il Python
restituivano zero binding senza alcun errore.

---

## 3. Riclassificazione degli uplink: definizione di "switch noto"

**Python** (`routers/mac.py`, `_reclassify_sightings` + `_mac_topology_uplinks`):
`known_switches` contiene **tutti** i nodi non-`Discovered` della network map.
Per uno switch presente in inventario ma di cui non è ancora stata raccolta la
topologia, `uplink_map` è vuota e quindi *ogni* porta viene riclassificata come
porta di accesso, azzerando gli uplink rilevati in fase di raccolta.

Il docstring della funzione dichiara però l'intento opposto:

> «per gli switch senza dati topologici si conserva il valore rilevato in
> raccolta (fallback)»

**Go**: è "noto" uno switch **per cui esistono dati topologici**. Senza
topologia si conserva il valore raccolto, come dice il docstring.

**Effetto**: il Go non azzera gli uplink su apparati non ancora scansionati per
la topologia. Aderisce all'intento dichiarato, non all'implementazione.

---

## 4. Concorrenza della scansione di sottorete

**Python** (`collectors/network_scanner.py`): due fasi separate — prima un ping
sweep su tutti gli host (`max_workers=50`), poi il triage SSH **solo** sugli
host risultati vivi.

**Go** (`internal/api/command_handlers.go`, `runScan`): ping e triage sono fusi
in un'unica goroutine per host, con `SetLimit(32)`.

**Conseguenza**: su una `/22` prevalentemente morta il Go tenta la connessione
SSH anche verso host irraggiungibili, con un profilo di carico diverso.

**Stato**: divergenza **non ancora sanata**. Da valutare se riportare il Go a
due fasi; è tracciata come rischio R7 nel piano di porting.

---

## 5. `mac.NormalizeMac` non segnala l'input non valido

Non è una divergenza dal Python ma un'incoerenza interna al Go, annotata qui
perché ha la stessa natura.

`internal/mac.NormalizeMac` ritorna la stringa di partenza (minuscola) quando
l'input non è un MAC valido, mentre il `normalize_mac` del Python ritorna
`None`. Il codice che deve distinguere "MAC completo" da "frammento di ricerca"
non può quindi usarla, e in `internal/store/arp.go` esiste
`normalizeMacStrict`, che ritorna anche un booleano di validità.

**Stato**: `NormalizeMac` non è stata modificata perché usata altrove e il
cambio di semantica avrebbe effetti non locali. Da unificare quando se ne
riesamina l'uso.

---

## 6. Trasporti NETCONF e RESTCONF per la MAC table

**Python** (`collectors/mac_collector.py`): tre livelli di trasporto —
NETCONF, poi RESTCONF, poi CLI.

**Go**: solo CLI.

**Motivo**: il CLI copre tutti i vendor presenti nel registro driver;
NETCONF richiederebbe una dipendenza nuova e non banale (RFC 6241 a mano
oppure `Juniper/go-netconf`). Rimandato finché non esiste un apparato che lo
richieda davvero.

**Stato**: rimandato per scelta, non dimenticato (§5.B punto 10 del piano).

---

## 7. `resolved_ip` della diagnosi client: stringa vuota invece di `null`

**Python** (`services/fortigate_service.py`, `diagnose_client`): quando il
client è indicato per MAC e la risoluzione in IP non riesce, la risposta
contiene `"resolved_ip": null`.

**Go** (`internal/fortigate/diagnose.go`): nello stesso caso il campo vale
`""`. Resta assente, come nel Python, quando il client era già un IP.

**Motivo**: distinguere "assente" da "presente e nullo" in Go richiede un
puntatore con marshalling personalizzato, per una differenza che nessun
consumatore sfrutta — il campo si legge con un test di verità, e sia `null`
sia `""` sono falsi. I consumatori sono l'assistente AI e il tool MCP, non
la dashboard.

**Effetto**: nullo per i chiamanti che controllano se il campo è valorizzato;
un chiamante che facesse `is None` andrebbe adeguato a un test di verità.

---

## 8. Il poller API non ha ripiego SSH

**Python** (`observability/ingesters/api_poller.py`): chiama
`get_system_status` e `get_interfaces`, che hanno entrambe il ripiego SSH.
Un apparato con la REST non raggiungibile viene quindi interrogato via SSH a
ogni giro di polling.

**Go** (`internal/observability/apipoller.go`): solo REST, passando `nil`
come SSHRunner.

**Motivo**: il poller gira in sottofondo su tutto l'inventario a intervalli
di `api_poll_s`. Un ripiego SSH trasforma ogni apparato irraggiungibile in
decine di secondi di attesa (dial + timeout), moltiplicate per il numero di
apparati, dentro un giro che dovrebbe essere leggero. Le viste interattive
mantengono il proprio ripiego SSH: lì l'attesa è richiesta da un operatore
che la sta aspettando.

**Effetto**: per un FortiGate con la sola SSH raggiungibile mancano gli
snapshot in `api_observations`, e il contesto dell'assistente AI su
quell'apparato è più povero. Nessuna funzione interattiva è degradata.


---

## 9. `/api/settings/app` espone solo le chiavi che il Go onora davvero

**Python** (`routers/settings.py`): la rotta gestisce otto chiavi — `port`,
`ssl_certfile`, `ssl_keyfile`, `cors_origins`, `no_browser` e le tre finestre di
retention dell'osservabilità.

**Go** (`internal/api/settings_handlers.go`): ne espone una, `port`. Le altre sono
rifiutate con `400 Invalid key: '<chiave>'`.

**Motivo**: il server Go non implementa TLS, CORS né l'apertura del browser.
Accettare `ssl_certfile` significherebbe far impostare un certificato a un operatore
che poi non ottiene HTTPS: un campo che mente è peggio di un campo assente, e il
rifiuto esplicito glielo dice subito invece di lasciarglielo scoprire quando l'HTTPS
non parte. Le tre finestre di retention **esistono** in Go, ma appartengono alla
configurazione dell'osservabilità (`/api/observability/config`), che è dove la UI le
modifica: duplicarle qui creerebbe due sorgenti per lo stesso valore.

`port` è invece onorato davvero: `ResolveListenAddr` lo legge all'avvio con la
precedenza env `SENTINELNET_PORT` > valore salvato > 8000, ed è coperto da test.

**Effetto**: il pannello "impostazioni avanzate" mostra il solo campo porta. Se in
futuro il Go acquisisce TLS e CORS, le chiavi vanno riaperte qui insieme alla
funzione — non prima.

---

## 10. Config analyzer: WLC AireOS analizzato come IOS (RISOLTA)

**Risolta**: `analyze_wlc_config` è ora portato in
`internal/configanalyzer/wlc.go` (`AnalyzeWLCConfig`) e il dispatch di
`backup.go` instrada `wlc-aireos` all'analizzatore dedicato. Copre entrambe le
piattaforme come il Python: AireOS (`show run-config commands`) e IOS-XE del
Catalyst 9800 (blocchi `wlan <profile> <id> <ssid>`, con `ios_base` allegato).
Output verificato byte-per-byte contro l'output vero del Python su fixture per
entrambe le piattaforme (`testdata/wlc_aireos.*`, `testdata/wlc_iosxe.*`).

**Nota routing**: vedi §11 per l'instradamento di `cisco_9800`.

## 11. Config analyzer: `cisco_9800` instradato all'analizzatore WLC

**Python** (`ai/config_analyzer.py`, `detect_config_type`): un vendor noto ma
non firewall/WLC — incluso `cisco_9800` — è rilevato come `ios`. Il ramo IOS-XE
di `analyze_wlc_config` esiste ma viene raggiunto solo da un device `cisco_wlc`
il cui contenuto è in realtà IOS-XE, oppure per sniffing del contenuto.

**Go** (`internal/fwanalyzer/detect.go`): `cisco_9800` è aggiunto al set dei
vendor WLC, quindi `DetectConfigType` ritorna `wlc-aireos` e il Catalyst 9800
passa da `AnalyzeWLCConfig`. `AnalyzeWLCConfig` distingue la piattaforma dal
contenuto (nessuna riga `config ...` ⇒ ramo IOS-XE), così un 9800 mostra la
tabella WLAN/SSID **e** conserva l'analisi IOS completa sotto `ios_base`.

**Motivo**: scelta esplicita dell'utente — "l'ultimo WLC Cisco è il C9800, deve
esserci compatibilità anche per quello". Instradarlo all'analizzatore WLC è
l'unico modo perché un 9800 etichettato normalmente in inventario mostri la
parte wireless invece dei soli campi IOS.

**Perimetro**: solo il vendor esatto `cisco_9800`. Il `cisco` generico resta
`ios` — mapparlo a WLC etichetterebbe come controller ogni switch Cisco.

**Effetto**: nessuna perdita di informazione (l'analisi IOS resta sotto
`ios_base`); `config_type` di un 9800 diventa `wlc-aireos` invece di `ios`.

---

## 12. MCP server: sottocomando invece di script separato

**Python**: il server MCP è uno script a sé (`ai/mcp_server.py`), avviato con
`python mcp_server.py` nella config del client LLM.

**Go**: è il sottocomando `sentinelnet mcp` del binario unico. Motivo:
distribuzione a singolo artefatto statico. Comportamento del protocollo, tabella
tool, auth e redazione sono 1:1 col Python; cambia solo `command`/`args` nella
config di Claude Desktop/Cline. Nessun'altra divergenza.

---

## 13. Default del modello Anthropic per l'AI provider

**Python** (`ai/ai_assistant.py`, `DEFAULT_MODELS`): il default per Anthropic
è `claude-3-5-sonnet-latest`.

**Go** (`internal/ai/models.go`, `DefaultModels`/`GetDefaultModel`): il default
per Anthropic è `claude-sonnet-5`.

**Motivo**: l'alias `claude-3-5-sonnet-latest` è datato e può non risolvere più
in futuro, facendo fallire il primo messaggio di chat di un profilo che non ha
impostato un modello esplicito. Il default si applica **solo** quando un profilo
non imposta un modello — l'utente può sovrascriverlo in qualsiasi momento via UI
o API. OpenAI (`gpt-4o-mini`), Gemini (`gemini-3-flash`), Ollama (`llama3`)
restano verbatim dal Python.

**Effetto**: una chat su Anthropic con profilo senza modello impostato usa
`claude-sonnet-5` anziché l'alias rischiato. Quando il profilo imposta un
modello, quello vince e non c'è divergenza.

---

## 14. Profili AI: nessuna migrazione dal formato legacy singolo

`routers/ai.py` (`_get_ai_profiles_raw`) migra, alla prima lettura, il vecchio
dict singolo `ai` di `app_settings.json` nella lista `ai_profiles`. Il server Go
non ha mai scritto quel formato: `loadProfiles` parte da lista vuota quando le
chiavi `ai_profiles`/`ai_active_profile` mancano, senza codice di migrazione.

`rate_limit_rpm` è persistito nel profilo come int semplice (0 = nessun limite).
Il tipo `*int` che distingue None da 0 riguarda solo il passaggio a `chat()`
(unità 2c), non lo storage del profilo.

---

## 15. Context builder AI: mac stats per-tenant e 404 su backup illeggibile

Porta dei `_*_context` di `routers/ai.py` (unità 2c-1).

- `deviceRunningConfigContext`: `configanalyzer.LoadBackupRunningConfig`
  collassa "nessun backup" e "file illeggibile" in un solo bool, quindi un
  backup presente ma illeggibile restituisce 404 anziché il 500 del Python. Il
  caso è di fatto irraggiungibile (il file è appena stato trovato da
  `FindFreshestBackup`).
- `tenantContextBlock`: le statistiche MAC del contesto tenant usano
  `store.MacStatsScoped([]string{tenant})` (conteggi filtrati per tenant, parità
  con `mac_history.stats(tenants=[tenant])`). `store.MacStats()` globale resta
  invariato per gli altri chiamanti.
