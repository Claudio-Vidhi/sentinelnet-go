package redact

import "strings"

import "testing"

// Fixture condivise con security/redaction.py: ogni caso deve essere mascherato
// da entrambe le implementazioni. Una divergenza qui è un segreto che trapela.
func TestTextRedactsEachPattern(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		secret string // non deve comparire nell'output
	}{
		{"enable secret", "enable secret 5 $1$abc$xyzHASH", "$1$abc$xyzHASH"},
		{"enable password", " enable password ClearPw123", "ClearPw123"},
		{"username secret", "username admin privilege 15 secret 5 $1$sAlT$h4sh", "$1$sAlT$h4sh"},
		{"username password", "username bob password 7 070C285F4D06", "070C285F4D06"},
		{"snmp community", "snmp-server community PrivateStr RO", "PrivateStr"},
		{"radius key", "radius-server host 10.0.0.1 key 7 04580A151C36", "04580A151C36"},
		{"bare key", " key 7 110A1016141D", "110A1016141D"},
		{"wpa psk", "wpa-psk ascii 0 SuperSecretPsk", "SuperSecretPsk"},
		{"fortios psksecret", "    set psksecret ENC 4kd93jfhs8", "ENC 4kd93jfhs8"},
		{"fortios passwd", "    set passwd MyF0rtiPass", "MyF0rtiPass"},
		{"api key", `api_key: "AKIA1234567890ABC"`, "AKIA1234567890ABC"},
		{"bearer", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9", "eyJhbGciOiJIUzI1NiJ9"},
		{"fernet blob", "token=gAAAAABm1234567890abcdefghijk_-", "gAAAAABm1234567890abcdefghijk_-"},
		{
			"pem block",
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nlinetwo\n-----END RSA PRIVATE KEY-----",
			"MIIEowIBAAKCAQEA",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Text(c.in)
			if strings.Contains(got, c.secret) {
				t.Fatalf("segreto non mascherato\n in: %q\nout: %q\nsegreto: %q", c.in, got, c.secret)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("maschera assente\n in: %q\nout: %q", c.in, got)
			}
		})
	}
}

func TestTextIsIdempotent(t *testing.T) {
	in := "enable secret 5 $1$abc$xyz\nsnmp-server community Private RO"
	once := Text(in)
	if twice := Text(once); twice != once {
		t.Fatalf("non idempotente:\n1: %q\n2: %q", once, twice)
	}
}

// Non deve mascherare ciò che non è un segreto: interfacce, VLAN, hostname, IP.
func TestTextPreservesNonSecrets(t *testing.T) {
	in := "interface GigabitEthernet0/1\n vlan 100\n hostname SW-CORE-01\n ip address 10.0.0.1 255.255.255.0"
	if got := Text(in); got != in {
		t.Fatalf("testo non segreto alterato:\n in: %q\nout: %q", in, got)
	}
}

func TestAnyWalksNestedStructures(t *testing.T) {
	in := map[string]any{
		"config": "enable secret 5 $1$abc$xyz",
		"list":   []any{"snmp-server community Private RO", 42},
		"n":      7,
	}
	out, ok := Any(in).(map[string]any)
	if !ok {
		t.Fatal("Any non ha restituito una mappa")
	}
	if strings.Contains(out["config"].(string), "$1$abc$xyz") {
		t.Error("segreto non mascherato nel valore stringa")
	}
	lst := out["list"].([]any)
	if strings.Contains(lst[0].(string), "Private") {
		t.Error("segreto non mascherato dentro la lista")
	}
	if lst[1] != 42 || out["n"] != 7 {
		t.Error("valori non-stringa alterati")
	}
	if _, exists := out["config"]; !exists {
		t.Error("chiave persa")
	}
}
