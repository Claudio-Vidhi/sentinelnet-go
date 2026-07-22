// Package api: endpoint dell'AI Assistant (/api/ai/chat, /api/ai/generate-config).
// Porta di ai_chat e ai_generate_config di routers/ai.py. Assembla il contesto
// dai builder di ai_context.go, rispetta il budget caratteri e delega a
// internal/ai.Chat (che applica il choke-point di redazione).
package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/ai"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
)

type aiChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

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

// activeProfile ritorna il profilo AI attivo o nil.
func (a *App) activeProfile() *aiProfile {
	list, active := a.loadProfiles()
	return findProfile(list, active)
}

// chatProfileAndKey risolve il profilo attivo e la sua chiave decifrata,
// scrivendo la risposta d'errore e ritornando ok=false se manca il profilo o
// (per provider non-ollama) la chiave. Condiviso da chat e generate-config.
func (a *App) chatProfileAndKey(w http.ResponseWriter) (*aiProfile, string, bool) {
	profile := a.activeProfile()
	if profile == nil {
		writeErr(w, http.StatusBadRequest, "Nessun profilo AI configurato/attivo. Un amministratore deve crearne uno prima.")
		return nil, "", false
	}
	apiKey := ""
	if profile.APIKeyEnc != "" {
		dec, err := a.vault.Decrypt(profile.APIKeyEnc)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return nil, "", false
		}
		apiKey = dec
	}
	if profile.Provider != "ollama" && apiKey == "" {
		writeErr(w, http.StatusBadRequest, "API key non configurata per il profilo AI attivo.")
		return nil, "", false
	}
	return profile, apiKey, true
}

// chatModelName: modello effettivo per la risposta (default per-provider se il
// profilo non ne fissa uno).
func chatModelName(profile *aiProfile) string {
	if profile.Model != "" {
		return profile.Model
	}
	return ai.GetDefaultModel(profile.Provider)
}

// runChat esegue ai.Chat con le opzioni del profilo e mappa gli errori
// (RateLimit → 429, Error → 502). Ritorna (reply, ok); su errore ha già scritto.
func (a *App) runChat(w http.ResponseWriter, profile *aiProfile, apiKey string, messages []ai.Message) (string, bool) {
	reply, err := ai.Chat(messages, ai.ChatOptions{
		Provider:        profile.Provider,
		Model:           profile.Model,
		APIKey:          apiKey,
		BaseURL:         profile.BaseURL,
		RateLimitRPM:    &profile.RateLimitRPM,
		AllowUnredacted: profile.AllowUnredacted,
	})
	if err != nil {
		var rl *ai.RateLimitError
		if errors.As(err, &rl) {
			writeErr(w, http.StatusTooManyRequests, rl.Error())
			return "", false
		}
		writeErr(w, http.StatusBadGateway, err.Error())
		return "", false
	}
	return reply, true
}

// handleAIChat: POST /api/ai/chat (utente autenticato). In questa fase gestisce
// profilo, chiave e la chat senza contesto; l'assemblaggio del contesto è
// aggiunto nei task successivi.
func (a *App) handleAIChat(w http.ResponseWriter, r *http.Request) {
	profile, apiKey, ok := a.chatProfileAndKey(w)
	if !ok {
		return
	}
	var req aiChatReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	messages := make([]ai.Message, len(req.Messages))
	for i, m := range req.Messages {
		messages[i] = ai.Message{Role: m.Role, Content: m.Content}
	}
	messages, ok = a.assembleChatContext(w, r, &req, profile, messages)
	if !ok {
		return
	}
	reply, ok2 := a.runChat(w, profile, apiKey, messages)
	if !ok2 {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"reply": reply, "provider": profile.Provider,
		"model": chatModelName(profile), "profile_name": profile.Name,
	})
}

// assembleChatContext costruisce i blocchi di contesto dagli attach flag e, se
// presenti, antepone un messaggio di sistema (contesto adattato al budget +
// blocco istruzioni fuori budget). Porta della parte contesto di ai_chat.
func (a *App) assembleChatContext(w http.ResponseWriter, r *http.Request, req *aiChatReq, profile *aiProfile, messages []ai.Message) ([]ai.Message, bool) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)

	var contextBlocks []string
	add := func(s string) { contextBlocks = append(contextBlocks, s) }

	if req.AttachInventory {
		add(a.deviceInventorySummary(scoped))
	}
	if req.AttachDeviceIP != "" {
		block, ok := a.deviceRunningConfigContext(w, r, req.AttachDeviceIP)
		if !ok {
			return nil, false
		}
		add(block)
	}
	for _, ip := range capStrings(req.AttachDeviceIPs, 20) {
		if ip == req.AttachDeviceIP {
			continue
		}
		block, ok := a.deviceRunningConfigContext(w, r, ip)
		if !ok {
			return nil, false
		}
		add(block)
	}
	if req.AttachTenant != "" {
		block, ok := a.tenantContextBlock(w, r, req.AttachTenant)
		if !ok {
			return nil, false
		}
		add(block)
	}
	if req.AttachFortigateIP != "" {
		block, ok := a.fortigateLiveContext(w, r, req.AttachFortigateIP)
		if !ok {
			return nil, false
		}
		add(block)
	}
	if req.AttachTopFlows || len(req.AttachFlowKeys) > 0 {
		var keys []obsstore.FlowKey
		if len(req.AttachFlowKeys) > 0 {
			if len(req.AttachFlowKeys) > 20 {
				writeErr(w, http.StatusBadRequest, "Troppi flussi selezionati: massimo 20 righe per analisi.")
				return nil, false
			}
			keys = make([]obsstore.FlowKey, len(req.AttachFlowKeys))
			for i, k := range req.AttachFlowKeys {
				keys[i] = obsstore.FlowKey{SrcIP: k.SrcIP, DstIP: k.DstIP, Protocol: k.Protocol, DstPort: k.DstPort}
			}
		}
		add(a.topFlowsContext(scoped, keys))
	}

	instructionBlocks := a.chatInstructionBlocks(req, claims.Role)

	if len(contextBlocks) == 0 && len(instructionBlocks) == 0 {
		return messages, true
	}
	budget := ai.ContextCharBudget(profile.Provider, profile.Model, profile.ContextBudgetChars)
	question := lastUserMessage(messages)
	contextBlocks = ai.FitContext(contextBlocks, budget, question)
	sys := ai.Message{Role: "system", Content: strings.Join(append(contextBlocks, instructionBlocks...), "\n\n")}
	return append([]ai.Message{sys}, messages...), true
}

func capStrings(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func lastUserMessage(messages []ai.Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			return messages[i].Content
		}
	}
	return ""
}

// chatInstructionBlocks ritorna il contratto di proposta config (§10.2) quando
// sono allegate running-config di dispositivi e l'utente è operator+. Il
// modello PROPONE, non esegue: il browser mostra la proposta e solo dopo
// conferma esplicita chiama /api/bulk-command (blacklist/RBAC/audit invariati).
// Tenuto FUORI dal budget: non va mai troncato. Porta di instruction_blocks.
func (a *App) chatInstructionBlocks(req *aiChatReq, role string) []string {
	if len(req.AttachDeviceIPs) == 0 || !roleAtLeast(role, "operator") {
		return nil
	}
	return []string{
		"Se l'utente chiede una modifica di configurazione su uno dei " +
			"dispositivi allegati, oltre alla spiegazione emetti UN blocco " +
			"recintato cosi (JSON su una riga, device_ip tra quelli allegati):\n" +
			"```sentinelnet-config\n" +
			`{"device_ip": "<ip>", "commands": ["<riga config>", "..."], ` +
			`"config_mode": true, "save_after": false}` + "\n" +
			"```\n" +
			"Non usare il blocco per comandi show/diagnostici. Non proporre " +
			"comandi distruttivi (reload, erase, write erase, format).",
	}
}

// handleAIGenerateConfig: POST /api/ai/generate-config (utente autenticato).
// Genera la config di un NUOVO switch del tenant da un template o dai parametri
// comuni dell'ambiente. Porta di ai_generate_config.
func (a *App) handleAIGenerateConfig(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	profile, apiKey, ok := a.chatProfileAndKey(w)
	if !ok {
		return
	}
	var req aiGenerateConfigReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	tenant := strings.TrimSpace(req.Tenant)
	hostname := strings.TrimSpace(req.Hostname)
	if tenant == "" || hostname == "" {
		writeErr(w, http.StatusBadRequest, "Tenant e hostname sono obbligatori.")
		return
	}
	if !a.assertGroupAllowed(w, r, tenant) {
		return
	}

	var context, source string
	if req.TemplateIP != "" {
		block, ok := a.deviceRunningConfigContext(w, r, req.TemplateIP)
		if !ok {
			return
		}
		context = block
		source = "la running-config del dispositivo template " + req.TemplateIP
	} else {
		block, ok := a.tenantCommonParameters(w, r, tenant)
		if !ok {
			return
		}
		context = block
		source = "i parametri comuni dell'ambiente del tenant"
	}

	requestLines := []string{"- hostname: " + hostname}
	if mgmt := strings.TrimSpace(req.MgmtIP); mgmt != "" {
		requestLines = append(requestLines, "- IP di management: "+mgmt)
	}
	if notes := strings.TrimSpace(req.Notes); notes != "" {
		if len(notes) > 1000 {
			notes = notes[:1000]
		}
		requestLines = append(requestLines, "- note aggiuntive: "+notes)
	}
	question := "Genera la configurazione completa proposta per un NUOVO switch del tenant '" + tenant +
		"', basandoti su " + source + ". Dati del nuovo switch:\n" + strings.Join(requestLines, "\n") + "\n" +
		"Riusa i parametri d'ambiente comuni (VLAN, VTP, NTP, syslog, AAA, DNS, SNMP, subnet di management) " +
		"adattandoli al nuovo dispositivo. Rispondi con UN solo blocco di codice contenente la configurazione " +
		"completa, seguito da brevi note sulle scelte fatte. Non inventare credenziali: usa segnaposti espliciti."

	budget := ai.ContextCharBudget(profile.Provider, profile.Model, profile.ContextBudgetChars)
	blocks := ai.FitContext([]string{context}, budget, question)
	messages := []ai.Message{
		{Role: "system", Content: strings.Join(blocks, "\n\n")},
		{Role: "user", Content: question},
	}
	reply, ok := a.runChat(w, profile, apiKey, messages)
	if !ok {
		return
	}
	a.auditLog("Config nuovo switch '" + hostname + "' (tenant '" + tenant + "') generata via AI dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{
		"reply": reply, "provider": profile.Provider,
		"model": chatModelName(profile), "profile_name": profile.Name,
	})
}
