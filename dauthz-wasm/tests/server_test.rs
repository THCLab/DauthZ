use dauthz_wasm::*;
use wasm_bindgen_test::*;

fn as_array(val: &wasm_bindgen::JsValue) -> js_sys::Array {
    js_sys::Array::from(val)
}

#[wasm_bindgen_test]
fn test_create_registration_challenge() {
    let mut service = DauthzService::new("test-service-aid", "http://example.com/oobi");
    let challenge = service.create_challenge("registration").unwrap();
    assert_eq!(challenge.purpose(), "registration");
    assert!(!challenge.nonce().is_empty());
    assert_eq!(challenge.service_aid(), "test-service-aid");
    assert!(!challenge.timestamp().is_empty());
    assert!(!challenge.expires_at().is_empty());
}

#[wasm_bindgen_test]
fn test_create_identification_challenge() {
    let mut service = DauthzService::new("svc-aid", "http://example.com/oobi");
    let challenge = service.create_challenge("identification").unwrap();
    assert_eq!(challenge.purpose(), "identification");
}

#[wasm_bindgen_test]
fn test_registration_flow() {
    let mut service = DauthzService::new("svc-aid", "http://svc.example.com/oobi");
    let challenge = service.create_challenge("registration").unwrap();
    let nonce = challenge.nonce();

    let response = JsChallengeResponse::new(
        "entity-aid-1",
        "http://entity.example.com/oobi",
        &nonce,
        "signed-data",
    );
    let result = service.handle_response(&response, true).unwrap();
    assert_eq!(result.kind(), "registered");
    assert_eq!(result.aid(), "entity-aid-1");
    assert!(!result.account_id().is_empty());
}

#[wasm_bindgen_test]
fn test_registration_rejects_invalid_signature() {
    let mut service = DauthzService::new("svc-aid", "http://svc.example.com/oobi");
    let challenge = service.create_challenge("registration").unwrap();
    let nonce = challenge.nonce();

    let response = JsChallengeResponse::new("entity-aid", "oobi", &nonce, "signed");
    let result = service.handle_response(&response, false).unwrap();
    assert_eq!(result.kind(), "invalid");
    assert_eq!(
        result.reason(),
        Some("signature verification failed".to_string())
    );
}

#[wasm_bindgen_test]
fn test_registration_rejects_duplicate() {
    let mut service = DauthzService::new("svc-aid", "http://svc.example.com/oobi");

    // First registration succeeds
    let ch1 = service.create_challenge("registration").unwrap();
    let resp1 = JsChallengeResponse::new("entity-1", "oobi", &ch1.nonce(), "signed");
    let r1 = service.handle_response(&resp1, true).unwrap();
    assert_eq!(r1.kind(), "registered");

    // Second registration with same AID fails
    let ch2 = service.create_challenge("registration").unwrap();
    let resp2 = JsChallengeResponse::new("entity-1", "oobi", &ch2.nonce(), "signed");
    let err = service.handle_response(&resp2, true);
    assert!(err.is_err());
}

#[wasm_bindgen_test]
fn test_login_flow() {
    let mut service = DauthzService::new("svc-aid", "http://svc.example.com/oobi");

    // Register first
    let ch_reg = service.create_challenge("registration").unwrap();
    let resp_reg = JsChallengeResponse::new("entity-1", "oobi", &ch_reg.nonce(), "signed");
    let _ = service.handle_response(&resp_reg, true).unwrap();

    // Login
    let ch_login = service.create_challenge("identification").unwrap();
    let resp_login = JsChallengeResponse::new("entity-1", "oobi", &ch_login.nonce(), "signed");
    let result = service.handle_response(&resp_login, true).unwrap();
    assert_eq!(result.kind(), "authenticated");
    assert_eq!(result.aid(), "entity-1");
    assert!(result.session_token().is_some());
}

#[wasm_bindgen_test]
fn test_login_rejects_unknown_account() {
    let mut service = DauthzService::new("svc-aid", "http://svc.example.com/oobi");

    let ch = service.create_challenge("identification").unwrap();
    let resp = JsChallengeResponse::new("unknown-aid", "oobi", &ch.nonce(), "signed");
    let err = service.handle_response(&resp, true);
    assert!(err.is_err());
}

#[wasm_bindgen_test]
fn test_challenge_nonce_consumed() {
    let mut service = DauthzService::new("svc-aid", "http://svc.example.com/oobi");

    let ch = service.create_challenge("registration").unwrap();
    let nonce = ch.nonce();

    // First use succeeds
    let resp = JsChallengeResponse::new("entity-1", "oobi", &nonce, "signed");
    let _ = service.handle_response(&resp, true).unwrap();

    // Reuse same nonce fails
    let resp2 = JsChallengeResponse::new("entity-2", "oobi", &nonce, "signed");
    let err = service.handle_response(&resp2, true);
    assert!(err.is_err());
}

#[wasm_bindgen_test]
fn test_list_and_remove_accounts() {
    let mut service = DauthzService::new("svc-aid", "http://svc.example.com/oobi");

    // Register two accounts
    for aid in ["entity-1", "entity-2"] {
        let ch = service.create_challenge("registration").unwrap();
        let resp = JsChallengeResponse::new(aid, "oobi", &ch.nonce(), "signed");
        let _ = service.handle_response(&resp, true).unwrap();
    }

    let accounts = service.list_accounts().unwrap();
    assert_eq!(as_array(&accounts).length(), 2);

    service.remove_account("entity-1").unwrap();

    let accounts = service.list_accounts().unwrap();
    assert_eq!(as_array(&accounts).length(), 1);
}

#[wasm_bindgen_test]
fn test_challenge_json_roundtrip() {
    let mut service = DauthzService::new("svc-aid", "http://svc.example.com/oobi");
    let challenge = service.create_challenge("registration").unwrap();

    let json = challenge.to_json().unwrap();
    let restored = JsChallenge::from_json(&json).unwrap();

    assert_eq!(restored.nonce(), challenge.nonce());
    assert_eq!(restored.service_aid(), challenge.service_aid());
    assert_eq!(restored.purpose(), challenge.purpose());
}

#[wasm_bindgen_test]
fn test_verification_result_to_json() {
    let mut service = DauthzService::new("svc-aid", "http://svc.example.com/oobi");
    let ch = service.create_challenge("registration").unwrap();
    let resp = JsChallengeResponse::new("entity-1", "oobi", &ch.nonce(), "signed");
    let result = service.handle_response(&resp, true).unwrap();

    let json = result.to_json().unwrap();
    assert!(json.is_object());
}
