package main

import (
	"encoding/json"
	"os"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/audit"
)

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	res, err := audit.RunNetSecAudit(string(b), "FGT01", "cis", os.Args[2])
	if err != nil {
		panic(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(res)
}
