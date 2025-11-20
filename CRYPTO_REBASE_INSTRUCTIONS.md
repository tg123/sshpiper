# Crypto Submodule Rebase - Completed ✓

## Summary
The crypto submodule has been successfully rebased onto the latest upstream golang/crypto (v0.44.0).

## What Was Done

### 1. Crypto Submodule Rebase
- **Old commit**: `2f530ebb8346d2ca897685185dcf35af5f1fc812` (v0.43.0-based)
- **New commit**: `a10554ad003aca9b20e6bf7fe090f8fcfbece67b` (v0.44.0-based)
- **Upstream base**: `4e0068c0098be10d7025c99ab7c50ce454c1f0f9` (golang/crypto master as of Nov 20, 2025)

### 2. Dependency Updates
The following dependencies were automatically updated by `go mod tidy`:
- `golang.org/x/crypto`: v0.43.0 → v0.44.0
- `golang.org/x/sync`: v0.17.0 → v0.18.0
- `golang.org/x/mod`: v0.28.0 → v0.29.0
- `golang.org/x/net`: v0.45.0 → v0.47.0
- `golang.org/x/sys`: v0.37.0 → v0.38.0
- `golang.org/x/term`: v0.36.0 → v0.37.0
- `golang.org/x/text`: v0.30.0 → v0.31.0
- `golang.org/x/tools`: v0.37.0 → v0.38.0

### 3. Verification
- ✅ Build successful: `go build ./...` passes
- ✅ Tests passing: `go test ./... -short` passes
- ✅ All sshpiper-specific changes preserved

## Rebased Commits
The rebase successfully applied 17 sshpiper-specific commits on top of 14 new upstream commits:

**Sshpiper changes (preserved):**
1. knownhost to support reader
2. refactor sshpiper api v1
3. auth return allowed methods remaining
4. fix empty upstream
5. remove wrong val
6. adopt official non auth callback
7. support drop pkg
8. expose ctx
9. adopt allow to configure public key auth algorithms on the server side
10. support partial succ
11. support max retry config
12. pipe banner from upstream
13. add reply hook support
14. refactor: rename callback functions for clarity and add upstream banner support
15. refactor: update CreateChallengeContext parameter type for consistency
16. refactor: update public key authentication algorithm handling for improved validation
17. refactor: replace custom contains function with slices.Contains for public key algorithm checks

**New upstream commits (from golang/crypto):**
1. go.mod: update golang.org/x dependencies
2. ssh: curb GSSAPI DoS risk by limiting number of specified OIDs
3. ssh/agent: prevent panic on malformed constraint
4. acme/autocert: let automatic renewal work with short lifetime certs
5. acme: pass context to request
6. ssh: fix error message on unsupported cipher
7. ssh: allow to bind to a hostname in remote forwarding
8. go.mod: update golang.org/x dependencies
9. all: eliminate vet diagnostics
10. all: fix some comments
11. chacha20poly1305: panic on dst and additionalData overlap
12. sha3: make it mostly a wrapper around crypto/sha3
13. ssh: use reflect.TypeFor instead of reflect.TypeOf
14. all: fix some typos in comment

## Important Note About Submodule

⚠️ **The crypto submodule commit `a10554ad003aca9b20e6bf7fe090f8fcfbece67b` exists only locally.**

### To Complete This Change:

Someone with write access to `https://github.com/tg123/sshpiper.crypto` needs to:

1. **Option A: Push the rebased branch**
   ```bash
   cd crypto
   git push --force-with-lease origin v1
   ```

2. **Option B: Work from this PR** 
   When this PR is merged into the main sshpiper repository, the maintainer can:
   - Extract the rebased crypto from this branch
   - Push it to tg123/sshpiper.crypto
   - Verify the submodule reference

### Alternative: If crypto repo push isn't desired
If pushing to the crypto repository is not feasible, the changes in this PR can still work for:
- Local builds (using the local crypto directory)
- Anyone who checks out this branch

However, for `git submodule update` to work for others, the commit must exist in the remote crypto repository.

## Security Benefits
The rebase includes important upstream security fixes:
- **ssh**: Curb GSSAPI DoS risk by limiting number of specified OIDs
- **ssh/agent**: Prevent panic on malformed constraint
- Various other improvements and bug fixes from upstream

## Files Changed
- `crypto` (submodule): Updated to rebased commit
- `go.mod`: Updated to reflect new crypto version (v0.44.0) and dependencies
- `go.sum`: Updated checksums for all dependencies
