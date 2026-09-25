# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```sh
cargo build                              # build all workspace crates
cargo build -p dauthz-core               # build a specific crate
cargo check                              # fast type-check
cargo clippy --all-targets -- -D warnings # lint (treat warnings as errors)
cargo fmt --all -- --check               # check formatting
cargo test -p dauthz-core                # run unit tests
cargo run -p dauthz-bin                  # list available test scenarios
cargo run -p dauthz-bin -- test-full     # run all ceremony scenarios end-to-end
```

The binary supports `test-registration`, `test-login`, `test-rotation`, and `test-full` subcommands. End-to-end scenarios require a `dkms` binary in PATH (or set `DKMS_BINARY` env var) and KERI infrastructure (witnesses on ports 3232/3233, watcher on 3235).

## Versioning & Releases

All workspace crates share one version, `[workspace.package] version` in the root `Cargo.toml` (crates use `version.workspace = true`). Releases are cut with cargo-release (`release.toml`) and git-cliff (`cliff.toml`):

```sh
cargo release patch|minor|major            # dry run: shows the bump and changelog hook
cargo release patch|minor|major --execute  # bump, prepend CHANGELOG.md, commit "chore: release X.Y.Z", tag vX.Y.Z
git push <remote> master --follow-tags     # pushing is manual (GitHub + Gerrit remotes)
```

Edit the generated CHANGELOG.md section before pushing if it needs prose. Commits must use Conventional Commits or git-cliff drops them from the changelog.

`dauthz-login-ui/VERSION` is versioned independently: other repos vendor the UI, so bump it on any asset change (see `dauthz-login-ui/README.md`).

## Architecture

Workspace with four crates:

```
dauthz-core      → shared protocol types (no crypto dependencies)
dauthz-client    → depends on dauthz-core; HTTP client SDK for Entity/SAS
dauthz-server    → depends on dauthz-core; server SDK for Service
dauthz-bin       → depends on all three; end-to-end test binary
```

### Protocol: Challenge-Response Ceremonies

DAuthZ implements a KERI-based authentication protocol with two ceremonies:

- **Registration**: Entity GETs challenge from `/dauthz/register`, signs it via dkms, POSTs response to `/dauthz/respond`. Service verifies signature and creates account.
- **Identification (Login)**: Same flow via `/dauthz/login`. Service verifies and issues a session token.
- **Key Rotation**: Entity rotates keys through dkms CLI, service verifies updated KEL.

### Key Design Decisions

**No KERI library dependency.** All cryptographic operations are delegated to the `dkms` CLI binary via subprocess calls. DAuthZ never holds private keys in memory — it only orchestrates ceremony flows and HTTP transport. The only interface to KERI is dkms stdout/stderr.

**Separate dkms aliases.** Client uses alias `"client"`, server uses `"service"`. Each has isolated state directories.

**File-based stores.** `AccountStore` and `ChallengeStore` persist as JSON files. No database dependency.

### Core Types (dauthz-core)

- `DauthzPayload` — protocol message with `i` (issuer AID), `o` (operation), `s` (session) fields
- `Challenge` / `ChallengeResponse` — challenge-response protocol types
- `SessionToken` — authenticated session result with expiration
- `CeremonyState` / `CeremonyPurpose` — state machine for ceremony lifecycle (Registration vs Identification)
- `DauthzError` — unified error type covering dkms CLI failures, transport errors, and protocol errors
