package provision

import "strings"

// Gestione dei segreti nel provisioning day-0 (finding I-2 dell'audit).
//
// Le config generate per visualizzazione o download NON devono contenere
// segreti in chiaro: i valori sensibili del payload del wizard sono
// sostituiti da un placeholder {{VAULT:<percorso>}} PRIMA di generare il
// testo. I valori reali sono usati solo al momento del push SSH/seriale, in
// memoria, senza mai essere persistiti né registrati.
//
// La generazione completamente materializzata resta possibile, ma solo con un
// flag esplicito e con una voce di audit.
//
// Il mascheramento lavora sul payload generico (map[string]any) e non sulla
// struct tipizzata: è lo stesso payload del wizard che il Python maschera, e
// vale per entrambi i provisioner (switch e FortiGate) senza doverne elencare
// i campi — un campo nuovo aggiunto domani è coperto per costruzione.

// secretKeyHints sono le sottostringhe che identificano un valore segreto nel
// payload del wizard: enable_secret, admin_password, snmpv3.auth_pass e
// priv_pass, ha.password, psksecret, aaa_key...
var secretKeyHints = []string{"password", "secret", "pass", "psk", "key"}

// IsSecretKey indica se il nome di un campo denota un valore sensibile.
func IsSecretKey(key string) bool {
	k := strings.ToLower(key)
	for _, h := range secretKeyHints {
		if strings.Contains(k, h) {
			return true
		}
	}
	return false
}

// MaskSecrets ritorna una copia del payload con ogni valore segreto
// sostituito da {{VAULT:<percorso.chiave>}}.
//
// I valori vuoti restano invariati: nel Python non generano righe di config, e
// sostituirli produrrebbe righe che nell'originale non esistono.
func MaskSecrets(v any) any {
	return maskSecrets(v, "")
}

func maskSecrets(v any, path string) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			switch inner := val.(type) {
			case map[string]any, []any:
				out[k] = maskSecrets(inner, p)
			case string:
				if IsSecretKey(k) && inner != "" {
					out[k] = "{{VAULT:" + p + "}}"
					continue
				}
				out[k] = val
			default:
				out[k] = val
			}
		}
		return out

	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			// Il percorso NON è indicizzato: tutti gli elementi di una lista
			// condividono lo stesso, come nel Python. Due server AAA danno
			// entrambi {{VAULT:aaa_servers.key}}, e il placeholder indica il
			// campo, non l'occorrenza.
			out[i] = maskSecrets(val, path)
		}
		return out
	}
	return v
}
