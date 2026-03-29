use std::path::PathBuf;

use dauthz_client::DauthzClient;
use dauthz_core::challenge::{CeremonyPurpose, ChallengeResponse};
use dauthz_server::DauthzService;

use crate::dkms::DkmsBridge;

const DKMS_BINARY_ENV: &str = "DKMS_BINARY";
const DKMS_BINARY_DEFAULT: &str = "dkms";

fn dkms_path() -> PathBuf {
    std::env::var(DKMS_BINARY_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DKMS_BINARY_DEFAULT))
}

fn witness_urls() -> Vec<&'static str> {
    vec!["http://172.17.0.1:3232", "http://172.17.0.1:3233"]
}

fn watcher_url() -> &'static str {
    "http://172.17.0.1:3235"
}

fn state_dir() -> PathBuf {
    std::env::temp_dir().join("dauthz-test")
}

fn write_oobi_file(oobi_data: &str, name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("dauthz-oobi");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{name}.json"));
    if oobi_data.starts_with('{') || oobi_data.starts_with('[') {
        let _ = std::fs::write(&path, oobi_data);
    } else {
        let json = serde_json::json!({ "oobi": oobi_data });
        let _ = std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap());
    }
    path
}

pub async fn test_registration() {
    println!("=== Registration Ceremony Test ===\n");

    let dkms_path = dkms_path();
    let state = state_dir();
    println!("dkms binary: {}", dkms_path.display());
    println!("state dir:   {}\n", state.display());

    if state.exists() {
        println!("State directory already exists: {}", state.display());
        println!("Remove it to start fresh? (y/N)");
        let mut answer = String::new();
        match std::io::stdin().read_line(&mut answer) {
            Ok(_) if answer.trim().eq_ignore_ascii_case("y") => {
                if let Err(e) = std::fs::remove_dir_all(&state) {
                    println!("Failed to remove state directory: {e}");
                    return;
                }
                println!("Removed.\n");
            }
            _ => {
                println!("Aborting.");
                return;
            }
        }
    }

    // 1. Create service AID via dkms
    let svc_bridge = DkmsBridge::new(&dkms_path, "test-service", &state.join("service"));
    let svc_aid = match svc_bridge
        .init_identifier(&witness_urls(), watcher_url())
        .await
    {
        Ok(info) => {
            println!("Service AID created: {}", info.aid);
            info.aid
        }
        Err(e) => {
            println!("Failed to create service AID: {e}");
            println!("Skipping — requires dkms binary and infrastructure");
            return;
        }
    };

    let svc_oobis = svc_bridge.get_oobi().await.unwrap_or_default();
    println!("Service OOBIs: {:?}", svc_oobis);
    let svc_oobi = svc_oobis
        .iter()
        .find(|o| !o.url.is_empty())
        .map(|o| o.url.clone())
        .unwrap_or_default();

    // 2. Create service SDK (no dkms dependency)
    let mut service = DauthzService::new(&state.join("service"), &svc_aid, &svc_oobi).unwrap();
    println!("Service SDK initialized\n");

    // 3. Create entity AID via dkms
    let entity_bridge = DkmsBridge::new(&dkms_path, "test-entity", &state.join("client"));
    let entity_aid = match entity_bridge
        .init_identifier(&witness_urls(), watcher_url())
        .await
    {
        Ok(info) => {
            println!("Entity AID created: {}", info.aid);
            info.aid
        }
        Err(e) => {
            println!("Failed to create entity AID: {e}");
            return;
        }
    };

    let entity_oobis = match entity_bridge.get_oobi().await {
        Ok(o) => o,
        Err(e) => {
            println!("Failed to get entity OOBI: {e}");
            return;
        }
    };
    let entity_oobi = entity_oobis
        .iter()
        .find(|o| !o.url.is_empty())
        .map(|o| serde_json::to_string(o).unwrap())
        .unwrap_or_default();
    let entity_oobi_url = entity_oobis
        .iter()
        .find(|o| !o.url.is_empty())
        .map(|o| o.url.clone())
        .unwrap_or_default();
    println!("Entity OOBI: {entity_oobi}");

    // 4. Server generates challenge
    let challenge = service
        .create_challenge(CeremonyPurpose::Registration)
        .unwrap();
    println!("Challenge issued: nonce={}", challenge.nonce);

    // 5. Client signs challenge via dkms
    let challenge_json = serde_json::to_string(&challenge).unwrap();
    println!("Signing challenge: {} bytes", challenge_json.len());
    let signed = match entity_bridge.sign(&challenge_json).await {
        Ok(s) => {
            println!("Challenge signed ({} bytes)", s.len());
            s
        }
        Err(e) => {
            println!("Failed to sign challenge: {e}");
            return;
        }
    };

    // 6. Server verifies signature via dkms
    let oobi_file = write_oobi_file(&serde_json::to_string(&entity_oobis).unwrap(), "entity");
    match svc_bridge.resolve_oobi(&oobi_file).await {
        Ok(()) => println!("Entity OOBI resolved OK"),
        Err(e) => {
            println!("OOBI resolution failed: {e}");
            return;
        }
    }
    println!("Verifying with -o: {entity_oobi}");
    let verified = svc_bridge
        .verify(&entity_oobi, &signed)
        .await
        .unwrap_or(false);
    println!("Signature verified: {verified}");

    // 7. Server handles response
    let response = ChallengeResponse {
        entity_aid: entity_aid.clone(),
        entity_oobi: entity_oobi.clone(),
        nonce: challenge.nonce.clone(),
        signed_challenge: signed,
    };

    match service.handle_response(response, verified).unwrap() {
        dauthz_core::verification::VerificationResult::Registered { aid, account_id } => {
            println!("\nRegistration successful!");
            println!("  AID:       {aid}");
            println!("  Account:   {account_id}");
        }
        dauthz_core::verification::VerificationResult::Invalid(reason) => {
            println!("\nRegistration failed: {reason}");
        }
        _ => unreachable!(),
    }
}

pub async fn test_login() {
    println!("=== Login Ceremony Test ===\n");

    let dkms_path = dkms_path();
    let state = state_dir();
    println!("dkms binary: {}", dkms_path.display());

    // 1. Load existing entity AID
    let entity_bridge = DkmsBridge::new(&dkms_path, "test-entity", &state.join("client"));
    let entity_aid = match entity_bridge.get_identifier_info().await {
        Ok(info) => {
            println!("Entity AID: {}", info.aid);
            info.aid
        }
        Err(e) => {
            println!("Failed to get entity AID: {e}");
            println!("Run test-registration first");
            return;
        }
    };

    let entity_oobis = match entity_bridge.get_oobi().await {
        Ok(o) => o,
        Err(e) => {
            println!("Failed to get entity OOBI: {e}");
            return;
        }
    };
    let entity_oobi = entity_oobis
        .iter()
        .find(|o| !o.url.is_empty())
        .map(|o| serde_json::to_string(o).unwrap())
        .unwrap_or_default();
    println!("Entity OOBI: {entity_oobi}");

    // 2. Load existing service AID
    let svc_bridge = DkmsBridge::new(&dkms_path, "test-service", &state.join("service"));
    let svc_aid = match svc_bridge.get_identifier_info().await {
        Ok(info) => {
            println!("Service AID: {}", info.aid);
            info.aid
        }
        Err(e) => {
            println!("Failed to get service AID: {e}");
            println!("Run test-registration first");
            return;
        }
    };

    let svc_oobis = svc_bridge.get_oobi().await.unwrap_or_default();
    let svc_oobi = svc_oobis
        .iter()
        .find(|o| !o.url.is_empty())
        .map(|o| o.url.clone())
        .unwrap_or_default();

    // 3. Load existing service SDK
    let mut service = DauthzService::new(&state.join("service"), &svc_aid, &svc_oobi).unwrap();
    println!("Service SDK initialized\n");

    // 4. Server generates identification challenge
    let challenge = service
        .create_challenge(CeremonyPurpose::Identification)
        .unwrap();
    println!("Challenge issued: nonce={}", challenge.nonce);

    // 5. Entity signs challenge
    let challenge_json = serde_json::to_string(&challenge).unwrap();
    let signed = match entity_bridge.sign(&challenge_json).await {
        Ok(s) => {
            println!("Challenge signed ({} bytes)", s.len());
            s
        }
        Err(e) => {
            println!("Failed to sign challenge: {e}");
            return;
        }
    };

    // 6. Server resolves entity OOBI and verifies
    let oobi_file = write_oobi_file(&serde_json::to_string(&entity_oobis).unwrap(), "entity");
    match svc_bridge.resolve_oobi(&oobi_file).await {
        Ok(()) => println!("Entity OOBI resolved OK"),
        Err(e) => {
            println!("OOBI resolution failed: {e}");
            return;
        }
    }
    let verified = svc_bridge
        .verify(&entity_oobi, &signed)
        .await
        .unwrap_or(false);
    println!("Signature verified: {verified}");

    // 7. Server handles response
    let response = ChallengeResponse {
        entity_aid: entity_aid.clone(),
        entity_oobi: entity_oobi.clone(),
        nonce: challenge.nonce.clone(),
        signed_challenge: signed,
    };

    match service.handle_response(response, verified).unwrap() {
        dauthz_core::verification::VerificationResult::Authenticated {
            aid,
            account_id,
            session_token,
        } => {
            println!("\nLogin successful!");
            println!("  AID:       {aid}");
            println!("  Account:   {account_id}");
            println!("  Token:     {session_token}");
        }
        dauthz_core::verification::VerificationResult::Invalid(reason) => {
            println!("\nLogin failed: {reason}");
        }
        _ => unreachable!(),
    }
}

pub async fn test_rotation() {
    println!("=== Rotation Ceremony Test ===\n");

    let dkms_path = dkms_path();
    let state = state_dir();
    println!("dkms binary: {}", dkms_path.display());

    let bridge = DkmsBridge::new(&dkms_path, "test-entity", &state.join("client"));
    let aid_info = match bridge.get_identifier_info().await {
        Ok(info) => info,
        Err(e) => {
            println!("Failed to get entity AID: {e}");
            println!("Run test-registration first");
            return;
        }
    };
    println!("Entity AID: {}", aid_info.aid);

    // Generate rotation config (inside dkms HOME so it can read it)
    let config_path = state.join("client").join("rotation_test-entity.yaml");
    let config = "\
witness_to_add: []
witness_to_remove: []
witness_threshold: 1
new_next_threshold: 1
";
    if let Err(e) = std::fs::write(&config_path, &config) {
        println!("Failed to write rotation config: {e}");
        return;
    }
    println!("Rotation config: {}", config_path.display());

    match bridge.rotate(&config_path).await {
        Ok(()) => println!("Rotation successful"),
        Err(e) => println!("Rotation failed: {e}"),
    }
}

pub async fn test_full_flow() {
    println!("=== Full End-to-End Test ===\n");

    test_registration().await;
    println!();
    test_rotation().await;
    println!();
    test_login().await;
}
