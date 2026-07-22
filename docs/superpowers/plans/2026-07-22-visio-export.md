# Visio Export Implementation Plan

**Goal:** Port `services/visio_export.py` into Go (`internal/export/visio.go`) and expose `POST /api/map/export/vsdx` in `internal/api/topology_handlers.go`.

## Task 1: Package `internal/export` & `.vsdx` Generator

**Files:**
- Create `internal/export/visio.go`
- Create `internal/export/visio_test.go`

- [ ] **Step 1**: Write unit tests in `internal/export/visio_test.go` that call `BuildVSDX` with sample nodes, edges, primitives, and connectors, and inspect the resulting ZIP archive (verifying all required OPC XML files exist and contain valid XML).
- [ ] **Step 2**: Implement `BuildVSDX` in `internal/export/visio.go` with XML helpers, coordinate scaling, bounds calculation, connection anchor registration, and ZIP writing.
- [ ] **Step 3**: Run `go test ./internal/export/` to verify tests pass cleanly.

## Task 2: API Handler & Route Registration

**Files:**
- Modify `internal/api/topology_handlers.go`
- Modify `internal/api/topology_handlers_test.go`
- Modify `internal/api/router.go`

- [ ] **Step 1**: Write an HTTP integration test in `internal/api/topology_handlers_test.go` for `POST /api/map/export/vsdx`.
- [ ] **Step 2**: Implement `handleExportMapVSDX` in `internal/api/topology_handlers.go`.
- [ ] **Step 3**: Register route `POST /api/map/export/vsdx` in `internal/api/router.go`.
- [ ] **Step 4**: Run `go test ./internal/api/` and `go build ./...` to verify clean compilation and passing tests.
