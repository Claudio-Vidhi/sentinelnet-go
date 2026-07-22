# AI Context Layer Implementation Plan (unit 2c-1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the six AI context builders from `routers/ai.py` into the Go server, plus the store/obsstore additions they need, as independently testable functions.

**Architecture:** New file `internal/api/ai_context.go` holds the builders as methods on `*App`, following the house `(w, r, …) → (string, bool)` write-to-w error convention. Supporting additions: `store.MacStatsScoped`, `obsstore.FlowKey`+`obsstore.TopFlowsContext`, `observability.Manager.FlowRetentionDays`, and a `fgtDeviceByIP` refactor. The two HTTP endpoints that consume these are unit 2c-2 (out of scope).

**Tech Stack:** Go stdlib, `database/sql`, existing `internal/{store,obsstore,observability,configanalyzer,fortigate,ai}` packages, go-chi.

## Global Constraints

- Builders that can fail take `(w http.ResponseWriter, r *http.Request, …)` and on failure call `writeErr(w, status, msg)` then return `ok=false`; builders that never fail return a plain `string`. No new error type.
- Tenant scoping via `scoped, _ := a.tenantsForUser(claims.Username, claims.Role)` (nil = admin/no restriction) + `canSeeTenant(scoped, tenant)`; device scoping via `a.assertDeviceAllowed(w, r, ip)`.
- Comments and audit/user-facing strings in Italian, matching surrounding code. Error/message text must match `routers/ai.py` verbatim where quoted.
- `FlowKey` is defined in the `obsstore` package (its query consumes it) to avoid an api→obsstore→api import cycle.
- Output text of every builder must match its Python counterpart field-for-field.
- Reference spec: `docs/superpowers/specs/2026-07-22-ai-context-layer-design.md`. Python source: `routers/ai.py`, `observability/summary.py`, `collectors/mac_history.py`.

---

## File Structure

- **Modify** `internal/store/mac.go` — add `MacStatsScoped`.
- **Modify** `internal/store/mac_test.go` (create if absent) — test it.
- **Modify** `internal/obsstore/queries.go` — add `FlowKey` + `TopFlowsContext`.
- **Modify** `internal/obsstore/queries_test.go` (create if absent) — test it.
- **Modify** `internal/observability/manager.go` — add `FlowRetentionDays`.
- **Modify** `internal/api/fortigate_handlers.go` — extract `fgtDeviceByIP`.
- **Create** `internal/api/ai_context.go` — the six builders.
- **Create** `internal/api/ai_context_test.go` — builder tests.
- **Modify** `docs/DIVERGENZE-DAL-PYTHON.md` — §15.

---

### Task 1: store.MacStatsScoped

**Files:**
- Modify: `internal/store/mac.go`
- Test: `internal/store/mac_test.go`

**Interfaces:**
- Produces: `func (s *Store) MacStatsScoped(tenants []string) (sightings, uniqueMacs, switches int, err error)`.
- Semantics: `tenants == nil` → global (all rows). `tenants` non-nil non-empty → `WHERE tenant IN (...)`. `tenants` non-nil empty → all zero, no query (ports Python's `if tenants is not None and not tenants: return zeros`).

- [ ] **Step 1: Write the failing test**

```go
package store

import "testing"

func seedSighting(t *testing.T, s *Store, mac, switchIP, tenant string) {
	t.Helper()
	if err := s.UpsertSighting(&MacSighting{Mac: mac, SwitchIP: switchIP, Tenant: tenant, Site: "central"}); err != nil {
		t.Fatal(err)
	}
}

func TestMacStatsScoped(t *testing.T) {
	s, err := Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })

	seedSighting(t, s, "aa:aa:aa:aa:aa:aa", "10.0.0.1", "acme")
	seedSighting(t, s, "bb:bb:bb:bb:bb:bb", "10.0.0.1", "acme")
	seedSighting(t, s, "cc:cc:cc:cc:cc:cc", "10.0.0.9", "globex")

	// Global (nil) sees all three sightings, two switches.
	sg, macs, sw, err := s.MacStatsScoped(nil)
	if err != nil {
		t.Fatal(err)
	}
	if sg != 3 || macs != 3 || sw != 2 {
		t.Fatalf("global: got sightings=%d macs=%d switches=%d, want 3/3/2", sg, macs, sw)
	}

	// Scoped to acme: two sightings, one switch.
	sg, macs, sw, _ = s.MacStatsScoped([]string{"acme"})
	if sg != 2 || macs != 2 || sw != 1 {
		t.Fatalf("acme: got %d/%d/%d, want 2/2/1", sg, macs, sw)
	}

	// Empty (non-nil) slice → all zero, no tenant visible.
	sg, macs, sw, _ = s.MacStatsScoped([]string{})
	if sg != 0 || macs != 0 || sw != 0 {
		t.Fatalf("empty scope: got %d/%d/%d, want 0/0/0", sg, macs, sw)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/store/ -run TestMacStatsScoped`
Expected: FAIL — `MacStatsScoped` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/store/mac.go` (near `MacStats`):

```go
// MacStatsScoped è come MacStats ma filtrato per tenant. tenants==nil = globale
// (nessun filtro); tenants non-nil vuoto = nessun tenant visibile → tutti zero
// (parità con mac_history.stats(tenants)). Usato dal contesto AI per-tenant.
func (s *Store) MacStatsScoped(tenants []string) (sightings, uniqueMacs, switches int, err error) {
	if tenants != nil && len(tenants) == 0 {
		return 0, 0, 0, nil
	}
	where := ""
	var args []any
	if tenants != nil {
		ph := make([]string, len(tenants))
		for i, t := range tenants {
			ph[i] = "?"
			args = append(args, t)
		}
		where = " WHERE tenant IN (" + strings.Join(ph, ",") + ")"
	}
	err = s.DB.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT mac), COUNT(DISTINCT switch_ip) FROM mac_sightings`+where, args...).
		Scan(&sightings, &uniqueMacs, &switches)
	return
}
```

If `strings` is not already imported in `mac.go`, add it.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/store/ -run TestMacStatsScoped`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/mac.go internal/store/mac_test.go
git commit -m "feat(store): MacStatsScoped per tenant (2c-1 task 1)"
```

---

### Task 2: obsstore.FlowKey + TopFlowsContext

**Files:**
- Modify: `internal/obsstore/queries.go`
- Test: `internal/obsstore/queries_test.go`

**Interfaces:**
- Consumes: existing `tenantClause(scope []string) (string, []any)`, `TopFlow` struct (fields `Tenant, SrcIP, DstIP string; Protocol *int; DstPort *int; TotalBytes, TotalPackets int64`), `Anomaly` struct (`Tenant, Kind, SrcIP, DstIP, SwitchPort string; Severity *int`).
- Produces:
  - `type FlowKey struct { SrcIP, DstIP string; Protocol int; DstPort *int }`
  - `func (s *Store) TopFlowsContext(cutoff int64, scope []string, keys []FlowKey, limit int) ([]TopFlow, []Anomaly, error)`
- Notes: flows grouped by `tenant, src_ip, dst_ip, protocol, dst_port`, ordered by `SUM(total_bytes) DESC`. Anomalies: `status != 'resolved'` and `created_ts >= now-86400`, newest 10. Tenant scope always ANDed for both.

- [ ] **Step 1: Write the failing test**

```go
package obsstore

import (
	"testing"
	"time"
)

func intp(v int) *int { return &v }

func TestTopFlowsContext(t *testing.T) {
	s, err := Open(t.TempDir() + "/obs.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })

	now := time.Now().Unix()
	ins := func(tenant, src, dst string, proto, dport int, bytes, pkts int64) {
		_, e := s.DB.Exec(`INSERT INTO flow_aggregates
			(window_start, tenant, src_ip, dst_ip, protocol, dst_port, total_bytes, total_packets, flow_count)
			VALUES (?,?,?,?,?,?,?,?,1)`, now-60, tenant, src, dst, proto, dport, bytes, pkts)
		if e != nil {
			t.Fatal(e)
		}
	}
	ins("acme", "10.0.0.1", "8.8.8.8", 6, 443, 5000, 50)
	ins("acme", "10.0.0.2", "1.1.1.1", 17, 53, 100, 2)
	ins("globex", "10.9.9.9", "8.8.4.4", 6, 80, 9999, 99)

	cutoff := now - 900

	// Scope acme → only acme rows, ordered by bytes desc.
	flows, _, err := s.TopFlowsContext(cutoff, []string{"acme"}, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("acme scope: got %d flows, want 2", len(flows))
	}
	if flows[0].SrcIP != "10.0.0.1" || flows[0].TotalBytes != 5000 {
		t.Errorf("order/bytes wrong: %+v", flows[0])
	}
	if flows[0].DstPort == nil || *flows[0].DstPort != 443 {
		t.Errorf("dst_port not carried: %+v", flows[0].DstPort)
	}

	// keys constraint: only the udp/53 tuple.
	flows, _, _ = s.TopFlowsContext(cutoff, []string{"acme"}, []FlowKey{
		{SrcIP: "10.0.0.2", DstIP: "1.1.1.1", Protocol: 17, DstPort: intp(53)},
	}, 20)
	if len(flows) != 1 || flows[0].SrcIP != "10.0.0.2" {
		t.Fatalf("keys constraint: got %d flows, want 1 (10.0.0.2)", len(flows))
	}

	// Scope must not leak globex even if a key names it.
	flows, _, _ = s.TopFlowsContext(cutoff, []string{"acme"}, []FlowKey{
		{SrcIP: "10.9.9.9", DstIP: "8.8.4.4", Protocol: 6, DstPort: intp(80)},
	}, 20)
	if len(flows) != 0 {
		t.Fatalf("scope leak: got %d flows, want 0", len(flows))
	}
}

func TestTopFlowsContextAnomalies(t *testing.T) {
	s, err := Open(t.TempDir() + "/obs.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	now := time.Now().Unix()
	_, err = s.DB.Exec(`INSERT INTO correlated_events
		(created_ts, tenant, kind, src_ip, dst_ip, switch_port, severity, status)
		VALUES (?,?,?,?,?,?,?,?)`, now-100, "acme", "scan", "10.0.0.5", "10.0.0.6", "Gi0/1", 3, "open")
	if err != nil {
		t.Fatal(err)
	}
	// A resolved one must be excluded.
	_, _ = s.DB.Exec(`INSERT INTO correlated_events
		(created_ts, tenant, kind, src_ip, dst_ip, switch_port, severity, status)
		VALUES (?,?,?,?,?,?,?,?)`, now-100, "acme", "old", "1.1.1.1", "2.2.2.2", "", 1, "resolved")

	_, anomalies, err := s.TopFlowsContext(now-900, []string{"acme"}, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 1 || anomalies[0].Kind != "scan" {
		t.Fatalf("anomalies: got %d (want 1 'scan'): %+v", len(anomalies), anomalies)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/obsstore/ -run TestTopFlowsContext`
Expected: FAIL — `FlowKey`/`TopFlowsContext` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/obsstore/queries.go`:

```go
// FlowKey vincola il contesto top-flussi a una tupla specifica (11.3). DstPort
// nil = confronto con dst_port IS NULL.
type FlowKey struct {
	SrcIP    string
	DstIP    string
	Protocol int
	DstPort  *int
}

// TopFlowsContext ritorna i top flussi aggregati della finestra (scoped per
// tenant, con opzionale vincolo per-tupla keys) e le anomalie correlate aperte
// delle ultime 24h. Porta di observability.summary.top_flows_context. Lo scope
// tenant è sempre in AND: i keys forniti dal client non estraggono righe di
// altri tenant.
func (s *Store) TopFlowsContext(cutoff int64, scope []string, keys []FlowKey, limit int) ([]TopFlow, []Anomaly, error) {
	clause, args := tenantClause(scope)

	flowClause := ""
	if len(keys) > 0 {
		parts := make([]string, 0, len(keys))
		kargs := []any{}
		for _, k := range keys {
			if k.DstPort == nil {
				parts = append(parts, "(src_ip = ? AND dst_ip = ? AND protocol = ? AND dst_port IS NULL)")
				kargs = append(kargs, k.SrcIP, k.DstIP, k.Protocol)
			} else {
				parts = append(parts, "(src_ip = ? AND dst_ip = ? AND protocol = ? AND dst_port = ?)")
				kargs = append(kargs, k.SrcIP, k.DstIP, k.Protocol, *k.DstPort)
			}
		}
		flowClause = " AND (" + strings.Join(parts, " OR ") + ")"
		args = append(args, kargs...)
	}

	flowParams := append([]any{cutoff}, args...)
	flowParams = append(flowParams, limit)
	rows, err := s.DB.Query(`
		SELECT tenant, src_ip, dst_ip, protocol, dst_port,
		       SUM(total_bytes), SUM(total_packets)
		FROM flow_aggregates
		WHERE window_start >= ?`+clause+flowClause+`
		GROUP BY tenant, src_ip, dst_ip, protocol, dst_port
		ORDER BY SUM(total_bytes) DESC
		LIMIT ?`, flowParams...)
	if err != nil {
		return nil, nil, err
	}
	flows := []TopFlow{}
	for rows.Next() {
		var f TopFlow
		if err := rows.Scan(&f.Tenant, &f.SrcIP, &f.DstIP, &f.Protocol, &f.DstPort, &f.TotalBytes, &f.TotalPackets); err != nil {
			rows.Close()
			return nil, nil, err
		}
		flows = append(flows, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// Anomalie correlate aperte, ultime 24h, scope tenant in AND.
	aClause, aArgs := tenantClause(scope)
	anomParams := append([]any{time.Now().Unix() - 86400}, aArgs...)
	arows, err := s.DB.Query(`
		SELECT tenant, COALESCE(kind,''), COALESCE(src_ip,''), COALESCE(dst_ip,''),
		       COALESCE(switch_port,''), severity
		FROM correlated_events
		WHERE status != 'resolved' AND created_ts >= ?`+aClause+`
		ORDER BY created_ts DESC
		LIMIT 10`, anomParams...)
	if err != nil {
		return nil, nil, err
	}
	defer arows.Close()
	anomalies := []Anomaly{}
	for arows.Next() {
		var a Anomaly
		if err := arows.Scan(&a.Tenant, &a.Kind, &a.SrcIP, &a.DstIP, &a.SwitchPort, &a.Severity); err != nil {
			return nil, nil, err
		}
		anomalies = append(anomalies, a)
	}
	return flows, anomalies, arows.Err()
}
```

Add `"time"` to the imports of `queries.go` if not already present.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/obsstore/ -run TestTopFlowsContext`
Expected: PASS (both TestTopFlowsContext and TestTopFlowsContextAnomalies).

- [ ] **Step 5: Commit**

```bash
git add internal/obsstore/queries.go internal/obsstore/queries_test.go
git commit -m "feat(obsstore): TopFlowsContext + FlowKey (2c-1 task 2)"
```

---

### Task 3: ai_context.go — inventory + running-config builders

**Files:**
- Create: `internal/api/ai_context.go`
- Test: `internal/api/ai_context_test.go`

**Interfaces:**
- Consumes: `a.tenantsForUser`, `canSeeTenant`, `a.store.ListDevices`, `a.assertDeviceAllowed`, `a.cfg.BackupDir()`, `configanalyzer.LoadBackupRunningConfig`, `claimsFrom`, `writeErr`.
- Produces:
  - `func (a *App) deviceInventorySummary(scoped []string) string`
  - `func (a *App) deviceRunningConfigContext(w http.ResponseWriter, r *http.Request, ip string) (string, bool)`

- [ ] **Step 1: Write the failing test**

```go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/config"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func mkCfg(dataDir string) *config.Config {
	return &config.Config{DataDir: dataDir}
}

func ctxAppWithDevices(t *testing.T) *App {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	must := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	must(st.UpsertDevice(&store.Device{IP: "10.0.0.1", Hostname: "sw1", Vendor: "cisco", Tenant: "acme", Site: "central"}))
	must(st.UpsertDevice(&store.Device{IP: "10.0.0.2", Vendor: "hp", Tenant: "globex", Site: "central"}))
	return NewApp(nil, st, nil, nil)
}

func adminCtxReq(ip string) *http.Request {
	req := httptest.NewRequest("POST", "/", nil)
	return req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "admin", Role: "admin"}))
}

func TestDeviceInventorySummaryScoping(t *testing.T) {
	app := ctxAppWithDevices(t)

	all := app.deviceInventorySummary(nil) // admin
	if !strings.Contains(all, "10.0.0.1") || !strings.Contains(all, "10.0.0.2") {
		t.Fatalf("admin summary should list both devices:\n%s", all)
	}
	if !strings.Contains(all, "(senza hostname)") {
		t.Errorf("device without hostname should show placeholder:\n%s", all)
	}

	acme := app.deviceInventorySummary([]string{"acme"})
	if !strings.Contains(acme, "10.0.0.1") || strings.Contains(acme, "10.0.0.2") {
		t.Fatalf("acme scope should only list acme device:\n%s", acme)
	}
}

func TestDeviceRunningConfigContextMissingBackup(t *testing.T) {
	app := ctxAppWithDevices(t)
	app.cfg = mkCfg(t.TempDir()) // empty backup dir
	w := httptest.NewRecorder()
	_, ok := app.deviceRunningConfigContext(w, adminCtxReq("10.0.0.1"), "10.0.0.1")
	if ok || w.Code != 404 {
		t.Fatalf("missing backup: ok=%v code=%d, want ok=false code=404", ok, w.Code)
	}
}

func TestDeviceRunningConfigContextUnknownDevice(t *testing.T) {
	app := ctxAppWithDevices(t)
	app.cfg = mkCfg(t.TempDir())
	w := httptest.NewRecorder()
	_, ok := app.deviceRunningConfigContext(w, adminCtxReq("9.9.9.9"), "9.9.9.9")
	if ok || w.Code != 404 {
		t.Fatalf("unknown device: ok=%v code=%d, want false/404", ok, w.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run 'TestDeviceInventorySummaryScoping|TestDeviceRunningConfigContext'`
Expected: FAIL — builders undefined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/api/ai_context.go`:

```go
// Package api: costruttori di contesto per l'AI Assistant (porta dei
// _*_context di routers/ai.py). Ogni funzione produce un blocco di testo già
// scoped per tenant/utente; l'assemblaggio e la redazione avvengono altrove
// (endpoint /api/ai/chat e choke-point in internal/ai). Convenzione d'errore:
// i builder che possono fallire scrivono la risposta su w e ritornano ok=false.
package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/configanalyzer"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

// deviceInventorySummary: riepilogo testuale dell'inventario, scoped per sede.
// scoped==nil = admin (nessun filtro). Porta di _device_inventory_summary.
func (a *App) deviceInventorySummary(scoped []string) string {
	devices, _ := a.store.ListDevices()
	filtered := make([]*store.Device, 0, len(devices))
	for _, d := range devices {
		if canSeeTenant(scoped, d.Tenant) {
			filtered = append(filtered, d)
		}
	}
	lines := []string{fmt.Sprintf("Inventario dispositivi (%d totali):", len(filtered))}
	shown := filtered
	if len(shown) > 200 {
		shown = shown[:200]
	}
	for _, d := range shown {
		host := d.Hostname
		if host == "" {
			host = "(senza hostname)"
		}
		lines = append(lines, fmt.Sprintf("- %s | %s | vendor=%s | sede=%s",
			d.IP, host, d.Vendor, d.Tenant))
	}
	if len(filtered) > 200 {
		lines = append(lines, fmt.Sprintf("... e altri %d dispositivi (troncato).", len(filtered)-200))
	}
	return strings.Join(lines, "\n")
}

// deviceRunningConfigContext: running-config più recente di un dispositivo,
// con verifica di scoping. Porta di _device_running_config_context.
func (a *App) deviceRunningConfigContext(w http.ResponseWriter, r *http.Request, ip string) (string, bool) {
	if _, ok := a.assertDeviceAllowed(w, r, ip); !ok {
		return "", false
	}
	text, ok := configanalyzer.LoadBackupRunningConfig(a.cfg.BackupDir(), ip)
	if !ok {
		writeErr(w, http.StatusNotFound, "Nessun backup trovato per "+ip+".")
		return "", false
	}
	return fmt.Sprintf("Running-config di %s:\n\n%s", ip, text), true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run 'TestDeviceInventorySummaryScoping|TestDeviceRunningConfigContext'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_context.go internal/api/ai_context_test.go
git commit -m "feat(ai): inventory + running-config context builders (2c-1 task 3)"
```

---

### Task 4: fgtDeviceByIP refactor + fortigateLiveContext

**Files:**
- Modify: `internal/api/fortigate_handlers.go`
- Modify: `internal/api/ai_context.go`
- Test: `internal/api/ai_context_test.go`

**Interfaces:**
- Consumes: existing `fgtDevice` internals (`assertDeviceAllowed`, `driver.IsFortinet`, `a.fgtClient`), `fortigate.Client.SystemStatus`, `fortigate.Client.FullConfig`, `fortigate.Result` (fields `Source string`, `Data any`).
- Produces:
  - `func (a *App) fgtDeviceByIP(w http.ResponseWriter, r *http.Request, ip string) (*store.Device, *fortigate.Client, bool)`
  - `func (a *App) fortigateLiveContext(w http.ResponseWriter, r *http.Request, ip string) (string, bool)`

**IMPLEMENTER: before writing Step 3, open `internal/api/fortigate_handlers.go` and read the current `fgtDevice` body and how `SystemStatus`/`FullConfig` are invoked in the FGT handlers; confirm the exact argument list (context + SSH runner) and the `fortigate.Result` field names. Match them.**

- [ ] **Step 1: Write the failing test**

```go
func TestFortigateLiveContextNotFortiGate(t *testing.T) {
	app := ctxAppWithDevices(t) // 10.0.0.1 is cisco, not a FortiGate
	app.cfg = mkCfg(t.TempDir())
	w := httptest.NewRecorder()
	_, ok := app.fortigateLiveContext(w, adminCtxReq("10.0.0.1"), "10.0.0.1")
	if ok || w.Code != 400 {
		t.Fatalf("non-fortigate: ok=%v code=%d, want false/400", ok, w.Code)
	}
}
```

(Live-data success against a fake FortiGate is exercised end-to-end in unit 2c-2; here we lock the resolution/scoping failure path, which is what `fortigateLiveContext` owns.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run TestFortigateLiveContextNotFortiGate`
Expected: FAIL — `fortigateLiveContext` undefined.

- [ ] **Step 3: Write minimal implementation**

In `internal/api/fortigate_handlers.go`, refactor `fgtDevice` to delegate. Replace the body of `fgtDevice` with:

```go
func (a *App) fgtDevice(w http.ResponseWriter, r *http.Request) (*store.Device, *fortigate.Client, bool) {
	return a.fgtDeviceByIP(w, r, chi.URLParam(r, "ip"))
}

// fgtDeviceByIP è come fgtDevice ma con l'IP esplicito (non dalla rotta), per i
// chiamanti che ricevono l'IP dal payload (es. contesto AI).
func (a *App) fgtDeviceByIP(w http.ResponseWriter, r *http.Request, ip string) (*store.Device, *fortigate.Client, bool) {
	d, ok := a.assertDeviceAllowed(w, r, ip)
	if !ok {
		return nil, nil, false
	}
	if !driver.IsFortinet(d.Vendor) {
		writeErr(w, http.StatusBadRequest, "il dispositivo non è un FortiGate")
		return nil, nil, false
	}
	c, err := a.fgtClient(ip)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return nil, nil, false
	}
	return d, c, true
}
```

Add to `internal/api/ai_context.go` (add imports `"context"` and `"encoding/json"`). The calls to `SystemStatus`/`FullConfig` below pass `context.Background(), nil` — **replace these with whatever the existing FGT handlers pass if it differs** (per the IMPLEMENTER note):

```go
// fortigateLiveContext: configurazione LIVE completa di un FortiGate + stato di
// sistema, best-effort. Porta di _fortigate_live_context. La risoluzione del
// device può fallire (scoping/vendor → risposta HTTP, ok=false); i fetch dei
// dati live no: eventuali errori finiscono come testo nel blocco.
func (a *App) fortigateLiveContext(w http.ResponseWriter, r *http.Request, ip string) (string, bool) {
	_, c, ok := a.fgtDeviceByIP(w, r, ip)
	if !ok {
		return "", false
	}
	lines := []string{fmt.Sprintf("## FortiGate %s — dati live", ip)}
	if st, err := c.SystemStatus(context.Background(), nil); err != nil {
		lines = append(lines, fmt.Sprintf("Stato sistema non disponibile: %v", err))
	} else {
		lines = append(lines, fmt.Sprintf("Stato sistema (fonte %s):\n%s",
			st.Source, truncRunes(jsonString(st.Data), 4000)))
	}
	if cfg, err := c.FullConfig(context.Background(), nil); err != nil {
		lines = append(lines, fmt.Sprintf("Configurazione live non disponibile: %v", err))
	} else {
		text := configText(cfg.Data)
		if len(text) > 120000 {
			text = text[:120000] + "\n... [config troncata]"
		}
		lines = append(lines, fmt.Sprintf("Configurazione completa (fonte %s):\n%s", cfg.Source, text))
	}
	return strings.Join(lines, "\n\n"), true
}

// jsonString serializza un valore per il contesto (equivalente di json.dumps
// ensure_ascii=False).
func jsonString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// configText: la config completa può essere già stringa (SSH) o struttura
// (REST); nel secondo caso la si serializza in JSON. Porta di
// `cfg["data"] if isinstance(cfg["data"], str) else json.dumps(...)`.
func configText(data any) string {
	if s, ok := data.(string); ok {
		return s
	}
	return jsonString(data)
}

func truncRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}
```

- [ ] **Step 4: Run test to verify it passes and the package builds**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run TestFortigateLiveContextNotFortiGate && go build ./...`
Expected: PASS + clean build.

- [ ] **Step 5: Commit**

```bash
git add internal/api/fortigate_handlers.go internal/api/ai_context.go internal/api/ai_context_test.go
git commit -m "feat(ai): fortigateLiveContext + fgtDeviceByIP refactor (2c-1 task 4)"
```

---

### Task 5: FlowRetentionDays accessor + tenantContextBlock

**Files:**
- Modify: `internal/observability/manager.go`
- Modify: `internal/api/ai_context.go`
- Test: `internal/api/ai_context_test.go`

**Interfaces:**
- Consumes: `a.store.TenantExists`, `a.store.ListTenants`, `a.store.ListDevices`, `a.store.GetSite`, `a.store.MacStatsScoped` (Task 1), `a.store.SearchSightings`, `a.obsMgr.FlowRetentionDays` (new), `ai.BuildTenantContext`, `ai.TenantContextArgs`.
- Produces:
  - `func (m *Manager) FlowRetentionDays() int`
  - `func (a *App) tenantContextBlock(w http.ResponseWriter, r *http.Request, tenant string) (string, bool)`

**IMPLEMENTER: confirm `Manager` has an unexported `cfg Config` field with `RetentionDays.FlowAggregates` before writing the accessor; and confirm `store.SearchSightings` signature `(mac, vlan, iface, switchIP string, tenants []string, limit int)` and `MacSighting` fields (`Mac, SwitchIP, Interface, Vlan, LastSeen`).**

- [ ] **Step 1: Write the failing test**

```go
func TestTenantContextBlockUnknownTenant(t *testing.T) {
	app := ctxAppWithDevices(t)
	w := httptest.NewRecorder()
	_, ok := app.tenantContextBlock(w, adminCtxReq(""), "nope")
	if ok || w.Code != 404 {
		t.Fatalf("unknown tenant: ok=%v code=%d, want false/404", ok, w.Code)
	}
}

func TestTenantContextBlockScoped(t *testing.T) {
	app := ctxAppWithDevices(t)
	if err := app.store.CreateTenant("acme", "Acme Corp"); err != nil {
		t.Fatal(err)
	}
	// A viewer scoped only to globex must get 403 for acme.
	req := httptest.NewRequest("POST", "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "bob", Role: "viewer"}))
	if err := app.store.SetUserTenants("bob", []string{"globex"}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	_, ok := app.tenantContextBlock(w, req, "acme")
	if ok || w.Code != 403 {
		t.Fatalf("out-of-scope tenant: ok=%v code=%d, want false/403", ok, w.Code)
	}

	// Admin gets the assembled block with the tenant device listed.
	w = httptest.NewRecorder()
	block, ok := app.tenantContextBlock(w, adminCtxReq(""), "acme")
	if !ok {
		t.Fatalf("admin block failed: code=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(block, "Contesto sede/tenant: acme") || !strings.Contains(block, "10.0.0.1") {
		t.Errorf("block missing header/device:\n%s", block)
	}
	if strings.Contains(block, "10.0.0.2") {
		t.Errorf("block leaked globex device:\n%s", block)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run TestTenantContextBlock`
Expected: FAIL — `tenantContextBlock` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/observability/manager.go`:

```go
// FlowRetentionDays è la finestra di retention (giorni) dei flow_aggregates,
// usata per annotare il contesto AI per-tenant. 0 se la retention è disattivata.
func (m *Manager) FlowRetentionDays() int { return m.cfg.RetentionDays.FlowAggregates }
```

Add to `internal/api/ai_context.go` (add import `"github.com/Claudio-Vidhi/sentinelnet-go/internal/ai"`):

```go
// tenantContextBlock: contesto completo di un tenant/sede (dispositivi, gruppo,
// sedi VPN, MAC history) scoped e verificato. Porta di _tenant_context_block.
func (a *App) tenantContextBlock(w http.ResponseWriter, r *http.Request, tenant string) (string, bool) {
	claims := claimsFrom(r.Context())
	exists, _ := a.store.TenantExists(tenant)
	if !exists {
		writeErr(w, http.StatusNotFound, "Sede/tenant '"+tenant+"' non trovata.")
		return "", false
	}
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	if !canSeeTenant(scoped, tenant) {
		writeErr(w, http.StatusForbidden, "tenant non consentito")
		return "", false
	}

	allDevices, _ := a.store.ListDevices()
	devices := []map[string]any{}
	siteIDs := map[string]bool{}
	for _, d := range allDevices {
		if d.Tenant != tenant {
			continue
		}
		devices = append(devices, map[string]any{
			"IP": d.IP, "Hostname": d.Hostname, "Vendor": d.Vendor, "Site": d.Site,
		})
		sid := d.Site
		if sid == "" {
			sid = "central"
		}
		siteIDs[sid] = true
	}

	var groupInfo map[string]any
	if tenants, err := a.store.ListTenants(); err == nil {
		for _, tn := range tenants {
			if tn.Name == tenant {
				groupInfo = map[string]any{"description": tn.Description}
				break
			}
		}
	}

	sites := []map[string]any{}
	for sid := range siteIDs {
		if s, err := a.store.GetSite(sid); err == nil && s != nil {
			site := map[string]any{"id": s.ID, "name": s.Name, "mode": s.Mode, "subnets": s.Subnets}
			if s.LastSeen != nil {
				site["last_seen"] = *s.LastSeen
			}
			sites = append(sites, site)
		}
	}

	sightings, macs, switches, _ := a.store.MacStatsScoped([]string{tenant})
	macStats := map[string]any{
		"sightings": sightings, "unique_macs": macs, "switches": switches,
	}
	if a.obsMgr != nil {
		macStats["retention_days"] = a.obsMgr.FlowRetentionDays()
	}

	recent, _ := a.store.SearchSightings("", "", "", "", []string{tenant}, 15)
	macRecent := make([]map[string]any, 0, len(recent))
	for _, s := range recent {
		macRecent = append(macRecent, map[string]any{
			"mac": s.Mac, "switch_ip": s.SwitchIP, "interface": s.Interface,
			"vlan": s.Vlan, "last_seen": s.LastSeen,
		})
	}

	return ai.BuildTenantContext(ai.TenantContextArgs{
		Tenant:    tenant,
		Devices:   devices,
		GroupInfo: groupInfo,
		Site:      sites,
		MacStats:  macStats,
		MacRecent: macRecent,
	}), true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run TestTenantContextBlock`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/observability/manager.go internal/api/ai_context.go internal/api/ai_context_test.go
git commit -m "feat(ai): tenantContextBlock + FlowRetentionDays (2c-1 task 5)"
```

---

### Task 6: tenantCommonParameters

**Files:**
- Modify: `internal/api/ai_context.go`
- Test: `internal/api/ai_context_test.go`

**Interfaces:**
- Consumes: `a.store.TenantExists`, `a.tenantsForUser`, `canSeeTenant`, `a.store.ListDevices`, `configanalyzer.LoadBackupRunningConfig`, `a.cfg.BackupDir()`.
- Produces: `func (a *App) tenantCommonParameters(w http.ResponseWriter, r *http.Request, tenant string) (string, bool)`.

**IMPLEMENTER: before writing the test, open `internal/configanalyzer/backup.go` and read `FindFreshestBackup` to learn the exact filename convention it matches under `BackupDir()`. Make `writeBackup` below create a file that `FindFreshestBackup` will actually find; do NOT change `FindFreshestBackup`.**

- [ ] **Step 1: Write the failing test**

```go
func TestTenantCommonParametersNoBackups(t *testing.T) {
	app := ctxAppWithDevices(t)
	app.cfg = mkCfg(t.TempDir()) // no backups on disk
	if err := app.store.CreateTenant("acme", ""); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	_, ok := app.tenantCommonParameters(w, adminCtxReq(""), "acme")
	if ok || w.Code != 404 {
		t.Fatalf("no backups: ok=%v code=%d, want false/404", ok, w.Code)
	}
}

func TestTenantCommonParametersDistill(t *testing.T) {
	app := ctxAppWithDevices(t)
	dir := t.TempDir()
	app.cfg = mkCfg(dir)
	if err := app.store.CreateTenant("acme", ""); err != nil {
		t.Fatal(err)
	}
	writeBackup(t, dir, "10.0.0.1", "hostname sw1\nntp server 10.0.0.250\nvlan 10\n name USERS\n")
	writeBackup(t, dir, "10.0.0.3", "hostname sw3\nntp server 10.0.0.250\n")
	if err := app.store.UpsertDevice(&store.Device{IP: "10.0.0.3", Vendor: "cisco", Tenant: "acme", Site: "central"}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	out, ok := app.tenantCommonParameters(w, adminCtxReq(""), "acme")
	if !ok {
		t.Fatalf("distill failed: code=%d", w.Code)
	}
	if !strings.Contains(out, "ntp server 10.0.0.250") {
		t.Errorf("shared ntp line should be common:\n%s", out)
	}
	if !strings.Contains(out, "VLAN in uso") || !strings.Contains(out, "10") {
		t.Errorf("vlan should be listed:\n%s", out)
	}
}
```

Add this helper (adjust the filename to match `FindFreshestBackup` per the IMPLEMENTER note) and imports `"os"`, `"path/filepath"`:

```go
func writeBackup(t *testing.T, dataDir, ip, content string) {
	t.Helper()
	dir := filepath.Join(dataDir, "backup-config")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, ip+"_20260101-000000.txt")
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run TestTenantCommonParameters`
Expected: FAIL — `tenantCommonParameters` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/api/ai_context.go` (add imports `"regexp"` and `"sort"`):

```go
// commonGlobalPrefixes: prefissi di comandi globali IOS considerati "parametri
// d'ambiente" comuni del tenant. Porta di _COMMON_GLOBAL_PREFIXES.
var commonGlobalPrefixes = []string{
	"vtp ", "ntp ", "logging ", "snmp-server ", "aaa ", "ip domain", "ip name-server",
	"ip default-gateway", "clock timezone", "clock summer-time", "spanning-tree ",
	"ip ssh ", "service ", "radius ", "tacacs ",
}

var (
	reVlanLine  = regexp.MustCompile(`^vlan (\d+)\s*$`)
	reIfaceVlan = regexp.MustCompile(`^interface vlan\s*(\d+)$`)
)

// tenantCommonParameters: distilla i parametri COMUNI dell'ambiente di rete di
// un tenant dai backup dei suoi dispositivi. Porta di _tenant_common_parameters.
func (a *App) tenantCommonParameters(w http.ResponseWriter, r *http.Request, tenant string) (string, bool) {
	claims := claimsFrom(r.Context())
	exists, _ := a.store.TenantExists(tenant)
	if !exists {
		writeErr(w, http.StatusNotFound, "Sede/tenant '"+tenant+"' non trovata.")
		return "", false
	}
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	if !canSeeTenant(scoped, tenant) {
		writeErr(w, http.StatusForbidden, "tenant non consentito")
		return "", false
	}

	allDevices, _ := a.store.ListDevices()
	lineCounts := map[string]int{}
	vlans := map[string]string{} // id -> name
	mgmtSubnets := map[string]bool{}
	analyzed := 0
	for _, d := range allDevices {
		if d.Tenant != tenant || d.IP == "" {
			continue
		}
		content, ok := configanalyzer.LoadBackupRunningConfig(a.cfg.BackupDir(), d.IP)
		if !ok {
			continue
		}
		analyzed++
		lines := strings.Split(content, "\n")
		for i, raw := range lines {
			s := strings.TrimSpace(raw)
			low := strings.ToLower(s)
			indented := strings.HasPrefix(raw, " ")
			if !indented && hasAnyPrefix(low, commonGlobalPrefixes) {
				lineCounts[s]++
			}
			if !indented {
				if m := reVlanLine.FindStringSubmatch(low); m != nil {
					name := ""
					if i+1 < len(lines) {
						nx := strings.TrimSpace(lines[i+1])
						if strings.HasPrefix(strings.ToLower(nx), "name ") {
							name = nx[5:]
						}
					}
					if _, seen := vlans[m[1]]; !seen {
						vlans[m[1]] = name
					}
				}
			}
		}
		if sub := mgmtSubnetFrom(lines); sub != "" {
			mgmtSubnets[sub] = true
		}
		if analyzed >= 15 {
			break
		}
	}
	if analyzed == 0 {
		writeErr(w, http.StatusNotFound, "Nessun backup di configurazione disponibile per il tenant '"+tenant+"'.")
		return "", false
	}

	threshold := (analyzed + 1) / 2
	if threshold < 1 {
		threshold = 1
	}
	common := []string{}
	for l, c := range lineCounts {
		if c >= threshold {
			common = append(common, l)
		}
	}
	sort.Strings(common)

	out := []string{fmt.Sprintf(
		"## Parametri comuni dell'ambiente tenant '%s' (derivati da %d dispositivi)", tenant, analyzed)}
	if len(vlans) > 0 {
		ids := make([]string, 0, len(vlans))
		for id := range vlans {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return atoiSafe(ids[i]) < atoiSafe(ids[j]) })
		parts := make([]string, 0, len(ids))
		for _, id := range ids {
			if vlans[id] != "" {
				parts = append(parts, fmt.Sprintf("%s (%s)", id, vlans[id]))
			} else {
				parts = append(parts, id)
			}
		}
		out = append(out, "VLAN in uso: "+strings.Join(parts, ", "))
	}
	if len(mgmtSubnets) > 0 {
		subs := make([]string, 0, len(mgmtSubnets))
		for s := range mgmtSubnets {
			subs = append(subs, s)
		}
		sort.Strings(subs)
		out = append(out, "Subnet di management osservate: "+strings.Join(subs, "; "))
	}
	if len(common) > 0 {
		out = append(out, "Comandi globali comuni (presenti su almeno metà dei dispositivi):")
		for i, l := range common {
			if i >= 120 {
				break
			}
			out = append(out, "  "+l)
		}
	}
	return strings.Join(out, "\n"), true
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// mgmtSubnetFrom cerca il primo blocco "interface vlan N" e, tra le sue righe
// indentate, la prima "ip address A M". Equivalente line-based del regex
// multiline del Python (evita le insidie di \s+ su newline in RE2).
func mgmtSubnetFrom(lines []string) string {
	for i, raw := range lines {
		if strings.HasPrefix(raw, " ") {
			continue
		}
		m := reIfaceVlan.FindStringSubmatch(strings.ToLower(strings.TrimSpace(raw)))
		if m == nil {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			if !strings.HasPrefix(lines[j], " ") && strings.TrimSpace(lines[j]) != "" {
				break // fine del blocco interface
			}
			f := strings.Fields(strings.TrimSpace(lines[j]))
			if len(f) >= 4 && f[0] == "ip" && f[1] == "address" {
				return fmt.Sprintf("VLAN %s: %s %s", m[1], f[2], f[3])
			}
		}
	}
	return ""
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run TestTenantCommonParameters`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_context.go internal/api/ai_context_test.go
git commit -m "feat(ai): tenantCommonParameters distillation (2c-1 task 6)"
```

---

### Task 7: topFlowsContext (api wrapper)

**Files:**
- Modify: `internal/api/ai_context.go`
- Test: `internal/api/ai_context_test.go`

**Interfaces:**
- Consumes: `a.obs.TopFlowsContext` (Task 2), `obsstore.FlowKey`, `obsstore.TopFlow`, `obsstore.Anomaly`.
- Produces: `func (a *App) topFlowsContext(scoped []string, keys []obsstore.FlowKey) string`.
- Window fixed at 900s, limit 20 (Python defaults).

- [ ] **Step 1: Write the failing test**

```go
import (
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
)

func TestTopFlowsContextBuilderEmpty(t *testing.T) {
	app := ctxAppWithDevices(t) // no obs wired
	out := app.topFlowsContext(nil, nil)
	if !strings.Contains(out, "Top flussi di rete") || !strings.Contains(out, "nessun flusso registrato") {
		t.Fatalf("empty/no-obs should still produce header + empty note:\n%s", out)
	}
}

func TestTopFlowsContextBuilderFormatsRows(t *testing.T) {
	app := ctxAppWithDevices(t)
	obs, err := obsstore.Open(t.TempDir() + "/obs.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { obs.DB.Close() })
	app.obs = obs
	now := time.Now().Unix()
	_, err = obs.DB.Exec(`INSERT INTO flow_aggregates
		(window_start, tenant, src_ip, dst_ip, protocol, dst_port, total_bytes, total_packets, flow_count)
		VALUES (?,?,?,?,?,?,?,?,1)`, now-60, "acme", "10.0.0.1", "8.8.8.8", 6, 443, 5000, 50)
	if err != nil {
		t.Fatal(err)
	}
	out := app.topFlowsContext([]string{"acme"}, nil)
	if !strings.Contains(out, "[acme] 10.0.0.1 → 8.8.8.8 TCP/443: 5000 byte, 50 pacchetti") {
		t.Errorf("row formatting wrong:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run TestTopFlowsContextBuilder`
Expected: FAIL — `topFlowsContext` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/api/ai_context.go` (add imports `"time"`, `"strconv"`, and `"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"`):

```go
var protoNames = map[int]string{6: "TCP", 17: "UDP", 1: "ICMP"}

// topFlowsContext: blocco markdown dei top flussi (900s, top 20) scoped per
// tenant, con opzionale vincolo per-tupla keys. Porta di top_flows_context.
// Se l'osservabilità non è collegata, ritorna comunque header + nota vuota.
func (a *App) topFlowsContext(scoped []string, keys []obsstore.FlowKey) string {
	const windowS = 900
	var flows []obsstore.TopFlow
	var anomalies []obsstore.Anomaly
	if a.obs != nil {
		cutoff := time.Now().Unix() - windowS
		flows, anomalies, _ = a.obs.TopFlowsContext(cutoff, scoped, keys, 20)
	}
	lines := []string{fmt.Sprintf("## Top flussi di rete (ultimi %d minuti, %d aggregati)", windowS/60, len(flows))}
	if len(flows) == 0 {
		lines = append(lines, "(nessun flusso registrato nella finestra)")
	}
	for _, f := range flows {
		proto := "?"
		if f.Protocol != nil {
			if name, ok := protoNames[*f.Protocol]; ok {
				proto = name
			} else {
				proto = strconv.Itoa(*f.Protocol)
			}
		}
		dport := "-"
		if f.DstPort != nil {
			dport = strconv.Itoa(*f.DstPort)
		}
		lines = append(lines, fmt.Sprintf("- [%s] %s → %s %s/%s: %d byte, %d pacchetti",
			f.Tenant, f.SrcIP, f.DstIP, proto, dport, f.TotalBytes, f.TotalPackets))
	}
	if len(anomalies) > 0 {
		lines = append(lines, "\n## Anomalie correlate aperte (ultime 24h)")
		for _, an := range anomalies {
			port := ""
			if an.SwitchPort != "" {
				port = " — porta " + an.SwitchPort
			}
			sev := "?"
			if an.Severity != nil {
				sev = strconv.Itoa(*an.Severity)
			}
			lines = append(lines, fmt.Sprintf("- [%s] %s sev=%s: %s → %s%s",
				an.Tenant, an.Kind, sev, an.SrcIP, an.DstIP, port))
		}
	}
	return strings.Join(lines, "\n")
}
```

The Python proto fallback prints the raw integer when unknown; here unknown protocol → its number. A nil protocol/severity (shouldn't happen for real rows) → "?".

- [ ] **Step 4: Run test to verify it passes and the three packages build**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run TestTopFlowsContextBuilder && go test ./internal/api/ ./internal/store/ ./internal/obsstore/`
Expected: PASS across all three packages.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_context.go internal/api/ai_context_test.go
git commit -m "feat(ai): topFlowsContext builder (2c-1 task 7)"
```

---

### Task 8: Document divergences §15

**Files:**
- Modify: `docs/DIVERGENZE-DAL-PYTHON.md`

- [ ] **Step 1: Append section §15**

Confirm the file currently ends at §14, then append:

```markdown
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
```

- [ ] **Step 2: Verify full build and vet**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go build ./... && go vet ./internal/api/ ./internal/store/ ./internal/obsstore/ ./internal/observability/`
Expected: no output (success).

- [ ] **Step 3: Commit**

```bash
git add docs/DIVERGENZE-DAL-PYTHON.md
git commit -m "docs: divergenza §15 (context builder AI: mac stats scoped, 404 backup)"
```

---

## Self-Review Notes

- **Spec coverage:** MacStatsScoped (T1), FlowKey+TopFlowsContext (T2), inventory+running-config builders (T3), fortigateLiveContext+fgtDeviceByIP (T4), FlowRetentionDays+tenantContextBlock (T5), tenantCommonParameters (T6), topFlowsContext (T7), §15 (T8). All six builders + three support additions + divergences mapped.
- **Import cycle:** `FlowKey` lives in obsstore (T2); the api builder (T7) imports obsstore, never the reverse.
- **Type consistency:** builders that can fail are `(w,r,…)→(string,bool)`; pure ones return `string`. `TopFlow`/`Anomaly` are the existing obsstore structs. `ai.TenantContextArgs` map keys match what `BuildTenantContext` reads (`IP/Hostname/Vendor/Site`, `sightings/unique_macs/switches/retention_days`, `mac/switch_ip/interface/vlan/last_seen`, site `id/name/mode/subnets/last_seen`, group `description`).
- **Implementer verification hooks:** T4 (FGT call args + Result fields), T5 (`Manager.cfg` field + `SearchSightings`/`MacSighting`), T6 (`FindFreshestBackup` filename convention) each carry an explicit "confirm before writing" note, since those signatures/behaviors live in unchanged code the task brief cannot fully show.
```
