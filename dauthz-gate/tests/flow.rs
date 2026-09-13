//! End-to-end ceremony over the axum router with the mock bridge:
//! init → callback → status → finish → /auth → logout, plus the refusal
//! paths and the credential presentation step.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use dauthz_core::sp_auth::{SpAuthEnvelope, ENVELOPE_V1, ENVELOPE_V2};
use dauthz_gate::bridge::mock::MockBridge;
use dauthz_gate::bridge::CheckState;
use dauthz_gate::ceremony::Gate;
use dauthz_gate::config::{Config, PolicyMode, Presentation};
use dauthz_gate::http::router;
use dauthz_gate::identity::ServiceIdentity;
use dauthz_gate::session::CookieCodec;
use http_body_util::BodyExt;
use tower::ServiceExt;

const USER: &str = "EUSERMAIN";
const DEVICE: &str = "EUSERDEVICE";
const ISSUER: &str = "EISSUER";
const SCHEMA: &str = "ESCHEMA";

struct Harness {
    app: Router,
    _gate: Arc<Gate>,
    bridge: Arc<MockBridge>,
}

fn config(mode: PolicyMode) -> Config {
    let mut c = Config::default();
    c.site.origin = "http://site.test".into();
    c.site.name = "Docs".into();
    c.cyfron.url = Some("http://mock".into());
    c.cyfron.token = Some("t".into());
    c.cookie.secure = false;
    c.policy.mode = mode;
    c.policy.allowed_aids = vec![USER.into()];
    if mode == PolicyMode::Credential {
        c.policy.schema_said = Some(SCHEMA.into());
        c.policy.issuer_aid = Some(ISSUER.into());
        c.policy.issuer_oobi = Some(r#"[{"cid":"EISSUER","role":"witness","eid":"B"}]"#.into());
    }
    c.validate().unwrap();
    c
}

async fn harness(cfg: Config) -> Harness {
    let bridge = Arc::new(MockBridge::new().with_identity("docs-gate-abcdef01", "EGATE"));
    let gate = Arc::new(Gate::new(
        cfg,
        bridge.clone(),
        CookieCodec::new("test-secret"),
    ));
    gate.set_identity(ServiceIdentity {
        alias: "docs-gate-abcdef01".into(),
        aid: "EGATE".into(),
        oobi: "[]".into(),
    })
    .await;
    Harness {
        app: router(gate.clone()),
        _gate: gate,
        bridge,
    }
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn oobi(aid: &str) -> String {
    format!(
        r#"[{{"eid":"BW","scheme":"http","url":"http://w/"}},{{"cid":"{aid}","role":"witness","eid":"BW"}}]"#
    )
}

fn envelope(v: &str, nonce: &str, aid: &str, said: Option<&str>) -> String {
    serde_json::to_string(&SpAuthEnvelope {
        v: v.into(),
        nonce: nonce.into(),
        entity_aid: aid.into(),
        disclosed_attributes: BTreeMap::new(),
        tos_hash: None,
        presented_credential_said: said.map(str::to_string),
    })
    .unwrap()
}

fn acdc(said: &str, holder: &str) -> String {
    format!(
        r#"{{"v":"ACDC10JSON0000fb_","d":"{said}","i":"{ISSUER}","ri":"EREG","s":"{SCHEMA}","a":{{"d":"EA","i":"{holder}","dt":"2026-01-01T00:00:00Z","role":"researcher"}}}}"#
    )
}

async fn init(h: &Harness, return_to: &str) -> serde_json::Value {
    let (status, _, body) = send(
        &h.app,
        Request::post(format!(
            "/dauthz/connect/init?return={}",
            dauthz_core::sp_auth::form_urlencode(return_to)
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str(&body).unwrap()
}

async fn callback(h: &Harness, body: serde_json::Value) -> (StatusCode, String) {
    let (s, _, b) = send(
        &h.app,
        Request::post("/dauthz/connect/callback")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "null")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    (s, b)
}

async fn status_of(h: &Harness, nonce: &str) -> serde_json::Value {
    let (_, _, b) = send(
        &h.app,
        Request::get(format!("/dauthz/connect/status?nonce={nonce}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    serde_json::from_str(&b).unwrap()
}

fn cookie_from(headers: &axum::http::HeaderMap) -> String {
    let set = headers
        .get(header::SET_COOKIE)
        .expect("Set-Cookie")
        .to_str()
        .unwrap();
    set.split(';').next().unwrap().to_string()
}

async fn auth_status(h: &Harness, cookie: Option<&str>) -> StatusCode {
    let mut req = Request::get("/dauthz/auth");
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    send(&h.app, req.body(Body::empty()).unwrap()).await.0
}

/// Run init → callback → status → finish for `signer` presenting `main`.
async fn sign_in(
    h: &Harness,
    main: &str,
    signer: &str,
    presented: Option<(String, String)>,
) -> (StatusCode, String, Option<(String, axum::http::HeaderMap)>) {
    let init = init(h, "/guides/x?tab=1").await;
    let nonce = init["nonce"].as_str().unwrap().to_string();
    let (v, said) = match &presented {
        Some((acdc, _)) => (
            ENVELOPE_V2,
            serde_json::from_str::<serde_json::Value>(acdc).unwrap()["d"]
                .as_str()
                .map(str::to_string),
        ),
        None => (ENVELOPE_V1, None),
    };
    let mut body = serde_json::json!({
        "nonce": nonce,
        "entity_oobi": oobi(main),
        "signed_challenge": MockBridge::sign_as(signer, &envelope(v, &nonce, main, said.as_deref())),
        "decision": "approve",
    });
    if let Some((acdc, sig)) = presented {
        body["presented_credential"] =
            serde_json::json!({ "acdc": acdc, "issuer_cesr": sig, "disclosed": ["role"] });
    }
    let (cb_status, cb_body) = callback(h, body).await;
    if cb_status != StatusCode::OK {
        return (cb_status, cb_body, None);
    }
    let st = status_of(h, &nonce).await;
    assert_eq!(st["state"], "approved", "{st}");
    let token = st["handoff_token"].as_str().unwrap();
    let (fin_status, headers, _) = send(
        &h.app,
        Request::get(format!("/dauthz/connect/finish?token={token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(fin_status, StatusCode::FOUND);
    (cb_status, cb_body, Some((token.to_string(), headers)))
}

#[tokio::test]
async fn happy_path_allowlist() {
    let h = harness(config(PolicyMode::Allowlist)).await;
    let init_resp = init(&h, "/guides/x?tab=1").await;
    let link = init_resp["deep_link"].as_str().unwrap();
    assert!(link.starts_with("cyfron://auth?nonce="));
    assert!(link.contains("callback_url=http%3A%2F%2Fsite.test%2Fdauthz%2Fconnect%2Fcallback"));
    assert!(!link.contains("requested_credentials"));
    assert_eq!(init_resp["finish_url"], "/dauthz/connect/finish");
    assert_eq!(
        status_of(&h, init_resp["nonce"].as_str().unwrap()).await["state"],
        "pending"
    );

    let (_, _, done) = sign_in(&h, USER, USER, None).await;
    let (token, headers) = done.unwrap();
    assert_eq!(headers.get(header::LOCATION).unwrap(), "/guides/x?tab=1");
    let cookie = cookie_from(&headers);
    assert!(headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("HttpOnly"));

    assert_eq!(auth_status(&h, Some(&cookie)).await, StatusCode::NO_CONTENT);
    assert_eq!(auth_status(&h, None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        auth_status(&h, Some("dauthz_session=garbage")).await,
        StatusCode::UNAUTHORIZED
    );

    // Handoff token is single use.
    let (replay, _, _) = send(
        &h.app,
        Request::get(format!("/dauthz/connect/finish?token={token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(replay, StatusCode::FORBIDDEN);

    // Logout clears the cookie; the old cookie still validates (stateless) but the browser drops it.
    let (s, headers, _) = send(
        &h.app,
        Request::get("/dauthz/logout").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::FOUND);
    assert!(headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));

    // whoami
    let (s, _, b) = send(
        &h.app,
        Request::get("/dauthz/whoami")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&b).unwrap()["aid"],
        USER
    );

    // The bridge saw resolve-oobi before verify-introduction, keyed on the main AID.
    assert_eq!(h.bridge.resolved.lock().unwrap().len(), 1);
    assert_eq!(h.bridge.verify_calls.lock().unwrap()[0].0, USER);
}

#[tokio::test]
async fn delegated_device_lands_on_the_main_aid_account() {
    let h = harness(config(PolicyMode::Allowlist)).await;
    // Unrelated device is refused.
    let (s, b, _) = sign_in(&h, USER, DEVICE, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    assert!(b.contains("signature verification failed"));

    h.bridge.delegate(DEVICE, USER);
    let (s, _, done) = sign_in(&h, USER, DEVICE, None).await;
    assert_eq!(s, StatusCode::OK);
    let cookie = cookie_from(&done.unwrap().1);
    let (_, _, b) = send(
        &h.app,
        Request::get("/dauthz/whoami")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let who: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(who["aid"], USER, "account keyed on the main AID");
    assert_eq!(who["signer_aid"], DEVICE);
}

#[tokio::test]
async fn refusal_paths() {
    let h = harness(config(PolicyMode::Allowlist)).await;

    // Not on the allowlist.
    let (s, b, _) = sign_in(&h, "ESTRANGER", "ESTRANGER", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(b.contains("allowlist"));

    // Wrong nonce inside the signed envelope.
    let init_resp = init(&h, "/").await;
    let nonce = init_resp["nonce"].as_str().unwrap();
    let (s, b) = callback(&h, serde_json::json!({
        "nonce": nonce, "entity_oobi": oobi(USER),
        "signed_challenge": MockBridge::sign_as(USER, &envelope(ENVELOPE_V1, "other-nonce", USER, None)),
    })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(b.contains("nonce"));
    assert_eq!(status_of(&h, nonce).await["state"], "denied");
    // The nonce was consumed: a second, correct callback is refused too.
    let (s, _) = callback(&h, serde_json::json!({
        "nonce": nonce, "entity_oobi": oobi(USER),
        "signed_challenge": MockBridge::sign_as(USER, &envelope(ENVELOPE_V1, nonce, USER, None)),
    })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Unknown nonce, user decline, malformed body.
    let (s, _) = callback(
        &h,
        serde_json::json!({"nonce": "nope", "entity_oobi": oobi(USER), "signed_challenge": "x"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let init_resp = init(&h, "/").await;
    let nonce = init_resp["nonce"].as_str().unwrap();
    let (s, _) = callback(&h, serde_json::json!({"nonce": nonce, "decision": "deny"})).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(status_of(&h, nonce).await["state"], "denied");
    let (s, _, _) = send(
        &h.app,
        Request::post("/dauthz/connect/callback")
            .body(Body::from("{"))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(status_of(&h, "unknown").await["state"], "expired");

    // Daemon outage is a refusal, never a pass.
    *h.bridge.fail_transport.lock().unwrap() = true;
    let (s, _, _) = sign_in(&h, USER, USER, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn login_page_injects_config_and_redirects_when_signed_in() {
    let h = harness(config(PolicyMode::Allowlist)).await;
    let (s, _, body) = send(
        &h.app,
        Request::get("/dauthz/login?return=/guides/x?tab=1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(r#""pluginBase":"/dauthz""#));
    assert!(body.contains(r#""returnTo":"/guides/x?tab=1""#));
    assert!(body.contains(r#""hideInvite":true"#));
    assert!(body.contains("/dauthz/ui/dauthz-login.js"));
    assert!(!body.contains("{{ASSET_BASE}}"));

    let (s, _, css) = send(
        &h.app,
        Request::get("/dauthz/ui/dauthz-login.css")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(css.contains(".card"));
    let (s, _, _) = send(
        &h.app,
        Request::get("/dauthz/ui/nope.js")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (_, _, done) = sign_in(&h, USER, USER, None).await;
    let cookie = cookie_from(&done.unwrap().1);
    let (s, headers, _) = send(
        &h.app,
        Request::get("/dauthz/login?return=/next")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::FOUND);
    assert_eq!(headers.get(header::LOCATION).unwrap(), "/next");

    // Off-site return targets collapse to "/".
    let (_, _, body) = send(
        &h.app,
        Request::get("/dauthz/login?return=//evil.test/x")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(body.contains(r#""returnTo":"/""#));
}

#[tokio::test]
async fn credential_mode_inline_presentation() {
    let h = harness(config(PolicyMode::Credential)).await;
    let init_resp = init(&h, "/").await;
    assert!(init_resp["deep_link"]
        .as_str()
        .unwrap()
        .contains("requested_credentials=ESCHEMA%40EISSUER"));

    // Without a credential the session is approved but not yet authorized.
    let (s, b, done) = sign_in(&h, USER, USER, None).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(b.contains(r#""needs_credential":true"#));
    let (_, headers) = done.unwrap();
    assert!(headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("/dauthz/present?return="));
    let cookie = cookie_from(&headers);
    assert_eq!(
        auth_status(&h, Some(&cookie)).await,
        StatusCode::UNAUTHORIZED
    );

    // With a valid passport in the callback the session is complete.
    let (s, b, done) = sign_in(
        &h,
        USER,
        USER,
        Some((acdc("ECRED", USER), MockBridge::issuer_sig(ISSUER))),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(b.contains(r#""needs_credential":false"#));
    let (_, headers) = done.unwrap();
    assert_eq!(headers.get(header::LOCATION).unwrap(), "/guides/x?tab=1");
    assert_eq!(
        auth_status(&h, Some(&cookie_from(&headers))).await,
        StatusCode::NO_CONTENT
    );

    // A passport issued to somebody else is refused even with a good signature.
    let (s, b, _) = sign_in(
        &h,
        USER,
        USER,
        Some((acdc("ECRED2", "ESOMEONE"), MockBridge::issuer_sig(ISSUER))),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(b.contains("issued to ESOMEONE"));

    // A revoked passport is refused under the default if_known policy.
    h.bridge.set_revocation("ECRED3", CheckState::Fail);
    let (s, b, _) = sign_in(
        &h,
        USER,
        USER,
        Some((acdc("ECRED3", USER), MockBridge::issuer_sig(ISSUER))),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(b.contains("revoked"));
}

#[tokio::test]
async fn credential_mode_page_presentation() {
    let h = harness(config(PolicyMode::Credential)).await;
    let (_, _, done) = sign_in(&h, USER, USER, None).await;
    let cookie = cookie_from(&done.unwrap().1);

    let (s, _, page) = send(
        &h.app,
        Request::get("/dauthz/present?return=/guides/x")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains(USER));
    assert!(page.contains("name=\"proof\""));

    let post = |proof: String| {
        let form = format!(
            "return=%2Fguides%2Fx&proof={}",
            dauthz_core::sp_auth::form_urlencode(&proof)
        );
        Request::post("/dauthz/present")
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form))
            .unwrap()
    };

    // Somebody else's proof: rejected, page re-rendered with the reason.
    let wrong = serde_json::json!({"acdc": acdc("EX", "ESOMEONE"), "issuer_cesr": MockBridge::issuer_sig(ISSUER)}).to_string();
    let (s, _, body) = send(&h.app, post(wrong)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("issued to ESOMEONE"));
    assert_eq!(
        auth_status(&h, Some(&cookie)).await,
        StatusCode::UNAUTHORIZED
    );

    // Garbage proof.
    let (s, _, body) = send(&h.app, post("not json".into())).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("proof is not JSON"));

    // The holder's own proof: cookie upgraded, redirected back.
    let good = serde_json::json!({"acdc": acdc("ECRED", USER), "issuer_cesr": MockBridge::issuer_sig(ISSUER), "disclosed": ["role"]}).to_string();
    let (s, headers, _) = send(&h.app, post(good)).await;
    assert_eq!(s, StatusCode::FOUND);
    assert_eq!(headers.get(header::LOCATION).unwrap(), "/guides/x");
    let upgraded = cookie_from(&headers);
    assert_eq!(
        auth_status(&h, Some(&upgraded)).await,
        StatusCode::NO_CONTENT
    );
    let (_, _, b) = send(
        &h.app,
        Request::get("/dauthz/whoami")
            .header(header::COOKIE, &upgraded)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&b).unwrap()["cred_said"],
        "ECRED"
    );

    // Without a cookie the page bounces to login.
    let (s, headers, _) = send(
        &h.app,
        Request::get("/dauthz/present").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::FOUND);
    assert!(headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("/dauthz/login"));
}

#[tokio::test]
async fn inline_only_presentation_refuses_a_bare_sign_in() {
    let mut cfg = config(PolicyMode::Credential);
    cfg.policy.presentation = Presentation::Inline;
    let h = harness(cfg).await;
    let (s, b, _) = sign_in(&h, USER, USER, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(b.contains("credential required"));
}

#[tokio::test]
async fn healthz_reports_readiness() {
    let cfg = config(PolicyMode::Open);
    let bridge = Arc::new(MockBridge::new());
    let gate = Arc::new(Gate::new(cfg, bridge, CookieCodec::new("k")));
    let app = router(gate.clone());
    let (s, _, b) = send(
        &app,
        Request::get("/dauthz/healthz").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert!(b.contains(r#""ready":false"#));
    let (s, _, _) = send(
        &app,
        Request::post("/dauthz/connect/init")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    gate.set_identity(ServiceIdentity {
        alias: "a".into(),
        aid: "E".into(),
        oobi: "[]".into(),
    })
    .await;
    let (s, _, b) = send(
        &app,
        Request::get("/dauthz/healthz").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(b.contains(r#""policy_mode":"open""#));
}
