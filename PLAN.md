# DAuthZ Implementation Plan

## Overview

DAuthZ (Decentralized Authorization) is a framework for identification and authorization based on KERI. This plan covers two deliverables:

1. **`dauthz-client`** — Client SDK for the Entity/SAS side. Orchestrates registration, identification, and rotation ceremonies. Delegates all key management, signing, and KEL operations to the `dkms` CLI binary.
2. **`dauthz-server`** — Server SDK for the Service side. Generates challenges, verifies responses, manages accounts. Delegates all cryptographic verification and KEL resolution to the `dkms` CLI binary.

**Key principle**: Neither SDK touches keys directly. The `dkms` binary (from `dkms-bin`) is the single source of truth for AID lifecycle, signing, verification, and KEL operations. DAuthZ orchestrates ceremony flows and HTTP transport, invoking `dkms` as a subprocess for every cryptographic operation.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          DAuthZ Protocol                                 │
├────────────────────────────────┬─────────────────────────────────────────┤
│       Client SDK               │           Server SDK                    │
│    (dauthz-client)             │        (dauthz-server)                  │
│                                │                                         │
│  ┌────────────────────────┐    │   ┌───────────────────────────┐        │
│  │ DauthzClient           │    │   │ DauthzService             │        │
│  │                        │    │   │                           │        │
│  │ - register(service_url)│◄───┼──►│ - create_challenge()     │        │
│  │ - login(service_url)   │    │   │ - verify_response(resp)  │        │
│  │ - rotate()             │    │   │ - manage_accounts()      │        │
│  └──────────┬─────────────┘    │   └──────────┬────────────────┘        │
│             │                  │              │                          │
│  ┌──────────┴─────────────┐    │   ┌──────────┴────────────────┐        │
│  │ DkmsBridge (client)    │    │   │ DkmsBridge (server)       │        │
│  │ - invoke dkms CLI      │    │   │ - invoke dkms CLI         │        │
│  │ - alias = "client"     │    │   │ - alias = "service"       │        │
│  └──────────┬─────────────┘    │   └──────────┬────────────────┘        │
│             │                  │              │                          │
│             ▼                  │              ▼                          │
│  ┌──────────────────────────────────────────────────────┐               │
│  │              dkms binary (dkms-bin)                   │               │
│  │                                                       │               │
│  │  identifier init / sign / verify / kel find / rotate  │               │
│  │  mesagkesto exchange / query / oobi resolve           │               │
│  │                                                       │               │
│  │  Manages: keys (seeds), KEL, OOBI, witnesses, db     │               │
│  └──────────────────────────┬───────────────────────────┘               │
│                             │                                           │
│                      ┌──────┴──────┐                                    │
│                      │ KERI Infra  │                                    │
│                      │ (dkms-demo) │                                    │
│                      │             │                                    │
│                      │ Witnesses   │                                    │
│                      │ Watcher     │                                    │
│                      │ MessageBox  │                                    │
│                      └─────────────┘                                    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## How dkms CLI Is Used

The `dkms` binary is a CLI tool that manages AID lifecycle. DAuthZ invokes it as a subprocess and parses stdout. Each party (client, service) uses a separate `dkms` alias to keep state isolated.

### dkms Commands Used by DAuthZ

| DAuthZ Operation | dkms Command | Purpose |
|------------------|-------------|---------|
| **Create AID** | `dkms identifier init -a <alias> --witness-url <url> --watcher-url <url>` | Generate new AID with witnesses |
| **Get AID** | `dkms identifier info -a <alias>` | Retrieve AID prefix for alias |
| **Get OOBI** | `dkms identifier oobi get -a <alias>` | Get OOBI for sharing with other party |
| **Resolve OOBI** | `dkms identifier oobi resolve -a <alias> --path <oobi_file>` | Resolve counter-party's OOBI |
| **Sign data** | `dkms data sign -a <alias> --data <json>` | Sign arbitrary data, returns CESR |
| **Verify data** | `dkms data verify -a <alias> --oobi <oobi> --message <cesr>` | Verify signed data against KEL |
| **Get KEL** | `dkms log kel find -a <alias> <identifier> --oobi <oobi>` | Fetch KEL of counter-party |
| **Rotate keys** | `dkms log kel rotate -a <alias> --config <yaml>` | Rotate AID keys |
| **Send to messagebox** | `dkms mesagkesto exchange -a <alias> --data <msg> --receiver-alias <alias>` | Exchange message via messagebox |
| **Pull mailbox** | `dkms mesagkesto query -a <alias>` | Pull pending messages from mailbox |
| **Export identifier** | `dkms identifier export -a <alias>` | Export identifier data |
| **Import identifier** | `dkms identifier import -a <alias>` | Import identifier data |

---

## Cargo Workspace Structure

```
dauthz/
├── Cargo.toml                 # Workspace root
├── PLAN.md                    # This file
├── dauthz.md                  # Protocol specification
│
├── dauthz-core/               # Shared types, payloads, errors (no dkms dependency)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── payload.rs         # DAuthZ payload (i, o, s fields)
│       ├── challenge.rs       # Challenge / ChallengeResponse types
│       ├── error.rs           # Unified error types
│       └── ceremony.rs        # Ceremony state machine types
│
├── dauthz-client/             # Client SDK (Entity/SAS side)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── client.rs          # DauthzClient — main entry point
│       ├── dkms.rs            # DkmsBridge — subprocess wrapper for dkms CLI
│       ├── ceremony/
│       │   ├── mod.rs
│       │   ├── registration.rs    # Registration ceremony
│       │   ├── identification.rs  # Login/identification ceremony
│       │   └── rotation.rs        # Key rotation ceremony
│       ├── transport.rs       # HTTP transport to Service + MessageBox
│       └── contact.rs         # Contact list management (service AID storage)
│
├── dauthz-server/             # Server SDK (Service side)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── service.rs         # DauthzService — main entry point
│       ├── dkms.rs            # DkmsBridge — subprocess wrapper for dkms CLI
│       ├── challenge.rs       # Challenge generation
│       ├── verification.rs    # Response verification (calls dkms verify + kel find)
│       ├── account.rs         # Account management (AID → account mapping)
│       └── transport.rs       # HTTP transport for witness/watcher queries
│
└── dauthz-bin/                # Example/test binary
    ├── Cargo.toml
    └── src/
        ├── main.rs            # CLI for testing ceremonies end-to-end
        └── scenarios.rs       # Registration, login, rotation test scenarios
```

---

## Dependencies

```toml
# dauthz-core — no keri dependencies, pure protocol types
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }

# dauthz-client / dauthz-server — no keri-controller dependency
[dependencies]
dauthz-core = { path = "../dauthz-core" }
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4"] }
```

No dependency on `keri-core`, `keri-controller`, or `teliox` at the DAuthZ level. All cryptographic operations go through `dkms` CLI.

---

## DkmsBridge — Subprocess Wrapper

The `DkmsBridge` is the core abstraction that replaces direct controller/signer usage. Both client and server SDKs use it to invoke `dkms` commands.

### `dauthz-client/src/dkms.rs` and `dauthz-server/src/dkms.rs`

```rust
pub struct DkmsBridge {
    /// Path to the dkms binary
    binary_path: PathBuf,
    /// Alias used for all dkms operations (e.g. "client" or "service")
    alias: String,
    /// Working directory for dkms state (~/.dkms-dev-cli/<alias>/)
    home_dir: PathBuf,
}

impl DkmsBridge {
    pub fn new(binary_path: &Path, alias: &str) -> Result<Self, DauthzError>;

    // ── AID Lifecycle ─────────────────────────────────────────────

    /// Initialize a new AID: `dkms identifier init -a <alias> --witness-url ... --watcher-url ...`
    pub async fn init_identifier(
        &self,
        witness_urls: &[&str],
        watcher_url: &str,
    ) -> Result<AidInfo, DauthzError>;

    /// Get identifier info: `dkms identifier info -a <alias>`
    pub async fn get_identifier_info(&self) -> Result<AidInfo, DauthzError>;

    /// Get OOBI: `dkms identifier oobi get -a <alias>`
    pub async fn get_oobi(&self) -> Result<Vec<OobiInfo>, DauthzError>;

    /// Resolve OOBI: `dkms identifier oobi resolve -a <alias> --path <file>`
    pub async fn resolve_oobi(&self, oobi_path: &Path) -> Result<(), DauthzError>;

    /// Export identifier: `dkms identifier export -a <alias>`
    pub async fn export_identifier(&self) -> Result<IdentifierExport, DauthzError>;

    // ── Signing ───────────────────────────────────────────────────

    /// Sign data: `dkms data sign -a <alias> --data <json>`
    /// Returns CESR-encoded signed message
    pub async fn sign(&self, data: &str) -> Result<String, DauthzError>;

    // ── Verification ──────────────────────────────────────────────

    /// Verify signed message: `dkms data verify -a <alias> --oobi <oobi> --message <cesr>`
    pub async fn verify(
        &self,
        oobis: &[&str],
        message: &str,
    ) -> Result<VerificationStatus, DauthzError>;

    // ── KEL Operations ────────────────────────────────────────────

    /// Get KEL: `dkms log kel find -a <alias> <identifier> --oobi <oobi>`
    pub async fn get_kel(
        &self,
        identifier: &str,
        oobi: Option<&str>,
    ) -> Result<String, DauthzError>;

    /// Rotate keys: `dkms log kel rotate -a <alias> --config <yaml>`
    pub async fn rotate(&self, config_path: &Path) -> Result<(), DauthzError>;

    // ── MessageBox ────────────────────────────────────────────────

    /// Exchange message: `dkms mesagkesto exchange -a <alias> --data <msg> --receiver-alias <alias>`
    pub async fn exchange_message(
        &self,
        data: &str,
        receiver_alias: &str,
    ) -> Result<String, DauthzError>;

    /// Pull mailbox: `dkms mesagkesto query -a <alias>`
    pub async fn query_mailbox(&self) -> Result<String, DauthzError>;
}

/// Parsed output of `dkms identifier info`
pub struct AidInfo {
    pub aid: String,
    pub registry_id: Option<String>,
    pub witnesses: Vec<String>,
    pub watchers: Vec<String>,
}

/// Parsed output of `dkms data verify`
pub enum VerificationStatus {
    Success,
    Issued,
    Revoked,
    NotFound,
}

/// Parsed output of `dkms identifier oobi get`
pub struct OobiInfo {
    pub scheme: String,
    pub url: String,
    pub eid: String,
    pub role: Option<String>,
}
```

**Implementation note**: Each method runs `dkms` as a subprocess via `tokio::process::Command`, captures stdout/stderr, and parses the output into structured types. The `home_dir` is set via the `DKMS_HOME` environment variable (or defaults to `~/.dkms-dev-cli/`).

---

## Phase 1: Core Types & Shared Protocol Layer

### 1.1 `dauthz-core/src/payload.rs` — DAuthZ Payload

The protocol payload format from the spec:

```rust
pub struct DauthzPayload {
    /// Initiator — OOBI identifying the initiating party (Entity or Service)
    pub i: String,
    /// Opponent — OOBI identifying the counter-party
    pub o: String,
    /// Signature — SAID (Self-Addressing Identifier) of the signed content
    pub s: String,
}
```

### 1.2 `dauthz-core/src/challenge.rs` — Challenge Types

```rust
/// Challenge issued by Service during registration or login ceremony.
pub struct Challenge {
    /// Random nonce for uniqueness (UUID v4)
    pub nonce: String,
    /// Service AID — who issued the challenge (string form of IdentifierPrefix)
    pub service_aid: String,
    /// MessageBox OOBI URL for the entity to submit responses
    pub msgbox_oobi: String,
    /// Service OOBI URL for the entity to verify service identity
    pub service_oobi: String,
    /// Timestamp (ISO 8601)
    pub timestamp: String,
    /// Purpose: "registration" or "identification"
    pub purpose: CeremonyPurpose,
}

/// Response from Entity/SAS to a challenge.
pub struct ChallengeResponse {
    /// Entity AID that signs the response (string form of IdentifierPrefix)
    pub entity_aid: String,
    /// Entity OOBI URL for the service to resolve the entity's KEL
    pub entity_oobi: String,
    /// Reference to the original challenge nonce
    pub nonce: String,
    /// CESR-encoded signed challenge (output of `dkms data sign`)
    pub signed_challenge: String,
}

pub enum CeremonyPurpose {
    Registration,
    Identification,
}
```

### 1.3 `dauthz-core/src/ceremony.rs` — Ceremony State Machine

```rust
pub enum CeremonyState {
    AwaitingChallenge,
    AwaitingApproval { challenge: Challenge },
    Responding { response: ChallengeResponse },
    Completed,
    Failed(String),
}
```

### 1.4 `dauthz-core/src/error.rs`

Unified error type covering subprocess failures, parse errors, HTTP errors, and protocol-specific errors.

---

## Phase 2: DkmsBridge Implementation

### `dauthz-client/src/dkms.rs` and `dauthz-server/src/dkms.rs`

Both SDKs share the same `DkmsBridge` pattern. Implementation details:

```rust
impl DkmsBridge {
    async fn run_command(&self, args: &[&str]) -> Result<CommandOutput, DauthzError> {
        let output = Command::new(&self.binary_path)
            .args(args)
            .env("HOME", &self.home_dir)
            .output()
            .await?;

        if !output.status.success() {
            return Err(DauthzError::DkmsError(String::from_utf8_lossy(&output.stderr).to_string()));
        }

        Ok(CommandOutput {
            stdout: String::from_utf8(output.stdout)?,
            stderr: String::from_utf8(output.stderr)?,
        })
    }
}
```

Each public method calls `run_command` with the appropriate arguments and parses stdout.

---

## Phase 3: Client SDK — Registration Ceremony

### `dauthz-client/src/ceremony/registration.rs`

Implements the registration flow from the spec:

```
Entity → Service:      Initiate registration (HTTP GET /dauthz/register)
Service → Entity:      Challenge with Service AID + MsgBox OOBI + Service OOBI
Entity → DkmsBridge:   Resolve Service OOBI (`dkms identifier oobi resolve`)
Entity → DkmsBridge:   Verify service KEL (`dkms log kel find`)
Entity → DkmsBridge:   Create or use existing AID (`dkms identifier init` or `dkms identifier info`)
Entity → DkmsBridge:   Sign challenge (`dkms data sign`)
Entity → Service:      ChallengeResponse with signed challenge + entity OOBI
Service → DkmsBridge:  Resolve Entity OOBI (`dkms identifier oobi resolve`)
Service → DkmsBridge:  Verify signed challenge (`dkms data verify`)
Service → Service:     Create account for entity AID
```

```rust
pub struct RegistrationCeremony<'a> {
    state: CeremonyState,
    dkms: &'a DkmsBridge,
    transport: &'a Transport,
    identifier_alias: Option<String>,
}

impl<'a> RegistrationCeremony<'a> {
    pub fn new(dkms: &'a DkmsBridge, transport: &'a Transport) -> Self;

    /// Step 1: Initiate — GET challenge from service
    pub async fn initiate(&mut self, service_url: &str) -> Result<Challenge, DauthzError>;

    /// Step 2: Verify service — resolve service OOBI + fetch KEL via dkms
    pub async fn verify_service(&mut self, challenge: &Challenge)
        -> Result<(), DauthzError>;

    /// Step 3: Prepare AID — create new alias or use existing
    pub async fn prepare_aid(&mut self, alias: Option<&str>) -> Result<String, DauthzError>;

    /// Step 4: Sign challenge via dkms and submit response to service
    pub async fn respond(&mut self) -> Result<(), DauthzError>;

    /// Run full ceremony end-to-end
    pub async fn run(
        &mut self,
        service_url: &str,
        alias: Option<&str>,
        witness_urls: &[&str],
        watcher_url: &str,
    ) -> Result<String, DauthzError>;
}
```

**Step-by-step dkms invocations during registration**:

| Step | DAuthZ action | dkms command |
|------|--------------|-------------|
| 1 | GET `/dauthz/register` from service | — |
| 2 | Resolve service OOBI | `dkms identifier oobi resolve -a client --path service_oobi.json` |
| 2 | Fetch service KEL | `dkms log kel find -a client <service_aid> --oobi <service_oobi>` |
| 3 | Create new AID (if needed) | `dkms identifier init -a <alias> --witness-url <url> --watcher-url <url>` |
| 3 | Get existing AID | `dkms identifier info -a <alias>` |
| 4 | Sign the challenge | `dkms data sign -a <alias> --data '<challenge_json>'` |
| 4 | Get entity OOBI | `dkms identifier oobi get -a <alias>` |
| 4 | POST ChallengeResponse to service | — |

---

## Phase 4: Client SDK — Identification Ceremony (Login)

### `dauthz-client/src/ceremony/identification.rs`

```
Entity → Service:      Initiate identification (HTTP GET /dauthz/login)
Service → Entity:      Identification challenge
Entity → DkmsBridge:   Resolve service OOBI (if not already known)
Entity → DkmsBridge:   Sign challenge (`dkms data sign`)
Entity → Service:      ChallengeResponse
Service → DkmsBridge:  Verify (`dkms data verify`)
Service → Entity:      Session token / access granted
```

```rust
pub struct IdentificationCeremony<'a> {
    state: CeremonyState,
    dkms: &'a DkmsBridge,
    transport: &'a Transport,
    alias: String,
}

impl<'a> IdentificationCeremony<'a> {
    pub fn new(dkms: &'a DkmsBridge, transport: &'a Transport, alias: &str) -> Self;

    /// Step 1: Request identification challenge
    pub async fn initiate(&mut self, service_url: &str)
        -> Result<Challenge, DauthzError>;

    /// Step 2: Verify service identity (skip if already in contacts)
    pub async fn verify_service(&mut self, challenge: &Challenge)
        -> Result<(), DauthzError>;

    /// Step 3: Sign and submit response
    pub async fn respond(&mut self) -> Result<SessionToken, DauthzError>;

    /// Run full ceremony end-to-end
    pub async fn run(&mut self, service_url: &str)
        -> Result<SessionToken, DauthzError>;
}
```

---

## Phase 5: Client SDK — Rotation Ceremony

### `dauthz-client/src/ceremony/rotation.rs`

```
Entity → DkmsBridge:   Generate new rotation config (new next seed, witness changes)
Entity → DkmsBridge:   Rotate keys (`dkms log kel rotate -a <alias> --config <yaml>`)
Entity → DkmsBridge:   Verify rotation propagated (`dkms log kel find`)
```

```rust
pub struct RotationCeremony<'a> {
    dkms: &'a DkmsBridge,
    alias: String,
}

impl<'a> RotationCeremony<'a> {
    pub fn new(dkms: &'a DkmsBridge, alias: &str) -> Self;

    /// Rotate keys using dkms CLI with provided rotation config
    pub async fn rotate(&self, config_path: &Path) -> Result<(), DauthzError>;

    /// Generate rotation config YAML (new seed, witnesses to add/remove)
    pub fn generate_rotation_config(
        &self,
        new_next_seed: &str,
        witnesses_to_add: &[&str],
        witnesses_to_remove: &[&str],
        witness_threshold: u64,
    ) -> Result<PathBuf, DauthzError>;

    /// Verify rotation by fetching updated KEL
    pub async fn verify_rotation(&self) -> Result<String, DauthzError>;
}
```

**dkms invocations**:
- `dkms log kel rotate -a <alias> --config rotation_config.yaml`
- `dkms log kel find -a <alias> <aid>` (verify)

---

## Phase 6: Client SDK — Main Entry Point

### `dauthz-client/src/client.rs`

```rust
pub struct DauthzClient {
    dkms: DkmsBridge,
    transport: Transport,
    contacts: ContactStore,
}

impl DauthzClient {
    /// Create client pointing to dkms binary, using given alias prefix
    pub fn new(
        dkms_binary: &Path,
        home_dir: &Path,
    ) -> Result<Self, DauthzError>;

    /// Initialize a new AID (calls `dkms identifier init`)
    pub async fn init_aid(
        &self,
        alias: &str,
        witness_urls: &[&str],
        watcher_url: &str,
    ) -> Result<AidInfo, DauthzError>;

    /// List existing AIDs
    pub async fn list_aids(&self) -> Result<Vec<AidInfo>, DauthzError>;

    /// Start registration ceremony with a service
    pub fn registration(&self) -> RegistrationCeremony;

    /// Start identification (login) ceremony
    pub fn identification(&self, alias: &str) -> IdentificationCeremony;

    /// Start key rotation ceremony
    pub fn rotation(&self, alias: &str) -> RotationCeremony;

    /// Get stored AID info for an alias
    pub async fn get_aid(&self, alias: &str) -> Result<AidInfo, DauthzError>;

    /// List known service contacts
    pub fn contacts(&self) -> &[ServiceContact];
}

pub struct ServiceContact {
    pub aid: String,
    pub url: String,
    pub alias: String,
    pub oobi: String,
}
```

---

## Phase 7: Server SDK — Challenge & Verification

### `dauthz-server/src/service.rs`

```rust
pub struct DauthzService {
    dkms: DkmsBridge,
    transport: Transport,
    account_store: AccountStore,
    challenge_store: ChallengeStore,
    alias: String,
}

impl DauthzService {
    /// Initialize service: ensure dkms alias exists with a service AID
    pub async fn new(
        dkms_binary: &Path,
        home_dir: &Path,
        alias: &str,
        witness_urls: &[&str],
        watcher_url: &str,
    ) -> Result<Self, DauthzError>;

    /// Load existing service from storage (alias already initialized)
    pub async fn load(
        dkms_binary: &Path,
        home_dir: &Path,
        alias: &str,
    ) -> Result<Self, DauthzError>;

    /// Get service AID (calls `dkms identifier info`)
    pub async fn aid(&self) -> Result<String, DauthzError>;

    /// Get service OOBI (calls `dkms identifier oobi get`)
    pub async fn oobi(&self) -> Result<Vec<OobiInfo>, DauthzError>;
}
```

### `dauthz-server/src/challenge.rs`

```rust
impl DauthzService {
    /// Generate a new challenge for registration or identification.
    /// The challenge contains: nonce, service AID, service OOBI, messagebox OOBI.
    pub fn create_challenge(&self, purpose: CeremonyPurpose)
        -> Result<Challenge, DauthzError>;
}
```

### `dauthz-server/src/verification.rs`

Verification uses dkms CLI to resolve the entity's KEL and verify the signed challenge:

```rust
impl DauthzService {
    /// Verify a challenge response.
    ///
    /// Steps:
    /// 1. Write entity OOBI to temp file
    /// 2. `dkms identifier oobi resolve -a service --path entity_oobi.json`
    /// 3. `dkms data verify -a service --oobi entity_oobi --message signed_challenge`
    /// 4. Check nonce matches active challenge
    /// 5. Check challenge not expired
    pub async fn verify_response(&self, response: &ChallengeResponse)
        -> Result<VerificationResult, DauthzError>;
}

pub enum VerificationResult {
    Registered { aid: String, account_id: String },
    Authenticated { aid: String, account_id: String, session_token: String },
    Invalid(String),
}
```

**dkms invocations during verification**:

| Step | dkms command |
|------|-------------|
| Resolve entity OOBI | `dkms identifier oobi resolve -a service --path /tmp/entity_oobi.json` |
| Fetch entity KEL | `dkms log kel find -a service <entity_aid> --oobi <entity_oobi>` |
| Verify signature | `dkms data verify -a service --oobi <entity_oobi> --message <signed_challenge>` |

### `dauthz-server/src/account.rs`

```rust
pub struct AccountStore {
    db: std::fs::File,  // Simple JSON file or redb
}

impl AccountStore {
    /// Create account for AID (registration)
    pub fn create_account(&self, aid: &str) -> Result<String, DauthzError>;

    /// Lookup account by AID (login)
    pub fn get_account(&self, aid: &str) -> Result<Option<Account>, DauthzError>;
}

pub struct Account {
    pub id: String,
    pub aid: String,
    pub created_at: String,
}
```

---

## Phase 8: Server SDK — Integration Interface

### HTTP Handler Methods

```rust
impl DauthzService {
    /// GET /dauthz/challenge — ceremony initiation endpoint
    pub async fn handle_challenge_request(
        &self,
        purpose: CeremonyPurpose,
    ) -> Result<Challenge, DauthzError> {
        let challenge = self.create_challenge(purpose)?;
        self.challenge_store.store(&challenge)?;
        Ok(challenge)
    }

    /// POST /dauthz/respond — challenge response endpoint
    pub async fn handle_challenge_response(
        &self,
        response: ChallengeResponse,
    ) -> Result<VerificationResult, DauthzError> {
        let challenge = self.challenge_store
            .get(&response.nonce)?
            .ok_or(DauthzError::UnknownChallenge)?;

        let result = self.verify_response(&response).await?;

        if matches!(result, VerificationResult::Invalid(_)) {
            return Ok(result);
        }

        self.challenge_store.consume(&response.nonce)?;

        match result {
            VerificationResult::Registered { .. } => {
                let account_id = self.account_store.create_account(&response.entity_aid)?;
                Ok(VerificationResult::Registered {
                    aid: response.entity_aid,
                    account_id,
                })
            }
            VerificationResult::Authenticated { .. } => {
                let account = self.account_store.get_account(&response.entity_aid)?
                    .ok_or(DauthzError::AccountNotFound)?;
                let token = generate_session_token();
                Ok(VerificationResult::Authenticated {
                    aid: response.entity_aid,
                    account_id: account.id,
                    session_token: token,
                })
            }
            other => Ok(other),
        }
    }
}
```

Integration example (pseudo-code for axum/actix):

```rust
let dauthz = DauthzService::new(
    Path::new("/usr/bin/dkms"),
    Path::new("./dauthz-state"),
    "my-service",
    &witness_urls,
    &watcher_url,
).await?;

router
    .route("/dauthz/register", get({
        let d = dauthz.clone();
        move || d.handle_challenge_request(CeremonyPurpose::Registration)
    }))
    .route("/dauthz/login", get({
        let d = dauthz.clone();
        move || d.handle_challenge_request(CeremonyPurpose::Identification)
    }))
    .route("/dauthz/respond", post({
        let d = dauthz.clone();
        move |body: Json<ChallengeResponse>| d.handle_challenge_response(body.0)
    }));
```

---

## Phase 9: Test Binary

### `dauthz-bin/`

CLI tool and automated test scenarios:

```rust
// End-to-end test scenario
async fn test_registration_and_login() {
    let dkms = Path::new("dkms");

    // 1. Start infrastructure (dkms-demo docker-compose must be running)
    let witness_urls = &["http://172.17.0.1:3232", "http://172.17.0.1:3233"];
    let watcher_url = "http://172.17.0.1:3235";

    // 2. Create service
    let service = DauthzService::new(
        dkms, Path::new("./test-state"), "test-service",
        witness_urls, watcher_url,
    ).await?;

    // 3. Create client
    let client = DauthzClient::new(dkms, Path::new("./test-state"))?;
    client.init_aid("test-client", witness_urls, watcher_url).await?;

    // 4. Registration ceremony
    let mut reg = client.registration();
    let aid = reg.run(
        "http://localhost:3000",
        Some("test-client"),
        witness_urls,
        watcher_url,
    ).await?;

    // 5. Login ceremony
    let mut login = client.identification("test-client");
    let session = login.run("http://localhost:3000").await?;
    assert!(session.is_valid());

    // 6. Key rotation
    let rot = client.rotation("test-client");
    let config = rot.generate_rotation_config(new_seed, &[], &[], 1)?;
    rot.rotate(&config).await?;
    rot.verify_rotation().await?;

    // 7. Login with rotated key
    let mut login2 = client.identification("test-client");
    let session2 = login2.run("http://localhost:3000").await?;
    assert!(session2.is_valid());
}
```

---

## Implementation Order & Milestones

| Milestone | Scope | Estimated Effort |
|-----------|-------|------------------|
| **M1** — Core types | `dauthz-core`: payload, challenge, error, ceremony types | 1-2 days |
| **M2** — DkmsBridge | Subprocess wrapper: init, sign, verify, kel, rotate, oobi | 2-3 days |
| **M3** — Transport | HTTP client for service endpoints + raw KERI infrastructure calls | 1-2 days |
| **M4** — Server challenge | Challenge generation, account store, challenge store | 1-2 days |
| **M5** — Server verification | Response verification via dkms (oobi resolve + data verify) | 2-3 days |
| **M6** — Registration ceremony | Client + server registration flow end-to-end | 2-3 days |
| **M7** — Identification ceremony | Client + server login flow | 1-2 days |
| **M8** — Rotation ceremony | Key rotation via dkms config generation + CLI call | 1 day |
| **M9** — Test binary & integration tests | `dauthz-bin` with scenarios against dkms-demo infra | 2-3 days |
| **M10** — Docs & examples | Integration guide, API docs, example service | 2-3 days |

**Total estimate: ~16-22 days**

---

## dkms CLI Command Mapping

Complete reference of how every DAuthZ operation maps to a dkms CLI invocation:

### Client-Side Operations

| Operation | dkms Command | Notes |
|-----------|-------------|-------|
| Create AID | `dkms identifier init -a <alias> --witness-url <url> --watcher-url <url>` | Called once per entity |
| Get AID info | `dkms identifier info -a <alias>` | Returns AID, witnesses, watchers |
| Get OOBI for sharing | `dkms identifier oobi get -a <alias>` | Returns JSON OOBI array |
| Resolve service OOBI | Write OOBI JSON to file, then `dkms identifier oobi resolve -a <alias> --path <file>` | Must resolve before verify |
| Fetch service KEL | `dkms log kel find -a <alias> <service_aid> --oobi <service_oobi>` | Verify service identity |
| Sign challenge | `dkms data sign -a <alias> --data '<challenge_json>'` | Returns CESR-encoded signed message |

### Server-Side Operations

| Operation | dkms Command | Notes |
|-----------|-------------|-------|
| Create service AID | `dkms identifier init -a <alias> --witness-url <url> --watcher-url <url>` | Called once at service setup |
| Get service OOBI | `dkms identifier oobi get -a <alias>` | Included in challenge |
| Resolve entity OOBI | Write OOBI JSON to file, then `dkms identifier oobi resolve -a <alias> --path <file>` | Must resolve before verify |
| Fetch entity KEL | `dkms log kel find -a <alias> <entity_aid> --oobi <entity_oobi>` | Load entity's key history |
| Verify signed challenge | `dkms data verify -a <alias> --oobi <entity_oobi> --message <cesr>` | Returns VerificationStatus |

### Rotation

| Operation | dkms Command | Notes |
|-----------|-------------|-------|
| Rotate keys | `dkms log kel rotate -a <alias> --config <yaml_path>` | Config specifies new seed, witness changes |
| Verify rotation | `dkms log kel find -a <alias> <aid>` | Confirm KEL updated |

---

## Advantages of CLI Delegation

1. **No duplicate key management** — dkms already has battle-tested key storage, seed management, and pre-rotation logic
2. **No KERI protocol reimplementation** — all CESR encoding/decoding, event processing, witness communication handled by dkms
3. **Simpler DAuthZ codebase** — DAuthZ only handles ceremony orchestration, HTTP transport, and account management
4. **Tested infrastructure** — dkms is validated against dkms-demo test vectors
5. **Loose coupling** — dkms can be upgraded independently; DAuthZ only depends on CLI interface stability
6. **Clear separation** — cryptographic operations in dkms, protocol flow in DAuthZ

---

## Considerations

### Performance
- Each dkms invocation spawns a subprocess (~50-100ms overhead). For high-throughput server scenarios, this is acceptable for authentication flows (not per-request).
- For login ceremonies, one verification = 3 dkms calls (resolve OOBI + KEL find + verify) ≈ 150-300ms total.

### State Isolation
- Client and server use different dkms aliases (`"client"` vs `"service"`) to keep KEL databases separate.
- Each alias has its own `~/.dkms-dev-cli/<alias>/db/` directory.

### Future: Library Migration
- If dkms-bin is refactored to expose a library crate (add `[lib]` + `pub mod`), DkmsBridge can switch from subprocess calls to direct function calls without changing the ceremony logic.
- The ceremony code depends only on the `DkmsBridge` trait interface, not on how commands are executed.

### Error Handling
- dkms CLI errors are captured from stderr and mapped to `DauthzError::DkmsError`.
- Parse errors from dkms stdout output are mapped to `DauthzError::ParseError`.
- HTTP transport errors use `DauthzError::TransportError`.

### Security
- Private keys never enter DAuthZ process memory — they stay inside dkms's filesystem-based key storage
- Challenge nonces are single-use and time-bounded
- Service verification on client side prevents MITM attacks
- No passwords stored server-side — accounts are purely AID-based
