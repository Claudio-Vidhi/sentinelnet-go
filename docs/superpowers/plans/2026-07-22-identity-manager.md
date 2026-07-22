# Identity Manager Implementation Plan

**Goal:** Port `security/identity_manager.py` into Go (`internal/store/identities.go` and `internal/api/identity_handlers.go`), providing credential profiles per tenant with AES-GCM vault encryption, tenant scoping, and `identity:<id>` resolution for device SSH connections.

## Task 1: Store Layer & Migration

**Files:**
- Create `internal/store/migrations/0011_identities.sql`
- Create `internal/store/identities.go`
- Create `internal/store/identities_test.go`

- [ ] **Step 1**: Write migration `0011_identities.sql` creating `identities` table and `idx_identities_tenant` index.
- [ ] **Step 2**: Write failing store unit test for `UpsertIdentity`, `ListIdentities`, `GetIdentity`, `DeleteIdentity` (including blocked deletion when devices use `identity:<id>`).
- [ ] **Step 3**: Implement store methods in `internal/store/identities.go`.
- [ ] **Step 4**: Run `go test ./internal/store/` to verify tests pass.

## Task 2: Decrypted Credentials Resolution

**Files:**
- Modify `internal/store/identities.go`
- Modify `internal/store/identities_test.go`

- [ ] **Step 1**: Write failing store test for `GetIdentityCredentials(id, vault)` verifying proper AES-GCM decryption of `password_enc` and `secret_enc`.
- [ ] **Step 2**: Implement `GetIdentityCredentials(id, vault)` in `internal/store/identities.go`.
- [ ] **Step 3**: Run `go test ./internal/store/` to verify tests pass.

## Task 3: API Handlers & Routes

**Files:**
- Create `internal/api/identity_handlers.go`
- Create `internal/api/identity_handlers_test.go`
- Modify `internal/api/router.go`

- [ ] **Step 1**: Write failing HTTP integration tests for GET/POST/PUT/DELETE `/api/identities`.
- [ ] **Step 2**: Implement HTTP handlers in `internal/api/identity_handlers.go`.
- [ ] **Step 3**: Register routes in `internal/api/router.go`.
- [ ] **Step 4**: Run `go test ./internal/api/` and `go build ./...` to verify clean build and passing tests.

## Task 4: Inventory Profile Resolution Integration

**Files:**
- Modify `internal/collect/triage.go` or device credential resolution to resolve `identity:<id>` profiles via `store.GetIdentityCredentials`.
- Test resolution behavior.
