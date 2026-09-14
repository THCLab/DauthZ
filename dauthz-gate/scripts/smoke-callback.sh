#!/usr/bin/env bash
# Headless "Connect with Cyfron" against a running dauthz-gate.
#
# Plays the wallet: mints a challenge, signs the canonical envelope with an
# identity on a cyfron-serviced you control, POSTs the callback, polls
# status, finishes with a cookie jar and checks the auth_request decision.
#
# Two modes:
#   MOCK=1            the gate runs with `serve --mock-bridge`; no daemon needed,
#                     the "signature" is the literal `-MOCK:<aid>` marker.
#   (default)         a real daemon: CYFRON_URL + CYFRON_TOKEN (or CYFRON_ENDPOINT_FILE)
#                     and USER_ALIAS name an identity there that signs the envelope.
#
# Env:
#   SITE_URL     default http://localhost:8080   (nginx in front of the gate)
#   GATE_PREFIX  default /dauthz
#   USER_AID     mock mode: the AID to present (must be allowlisted / policy-open)
#   USER_ALIAS   real mode: alias on the daemon, created if missing (default smoke-user)
#   WITNESS_LOCATION / WATCHER_LOCATION
#                real mode: LocationScheme JSON for a created identity, so the
#                SP-side daemon can resolve its KEL (public dkms witnesses by default)
#   PRESENT_FILE real mode: JSON file with {acdc, issuer_cesr, said} (the output of
#                sandbox/passport.sh) to present as a credential in the callback
#   PRESENT_MODE inline (default): the credential rides in the callback (envelope v2);
#                page: sign in without it, then POST the proof to /present with the cookie
#   EXPECT_DENY  set to 1 to assert the callback is refused (e.g. AID not allowlisted)

set -euo pipefail
SITE_URL="${SITE_URL:-http://localhost:8080}"
GATE_PREFIX="${GATE_PREFIX:-/dauthz}"
BASE="$SITE_URL$GATE_PREFIX"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

echo "-> POST $BASE/connect/init"
INIT=$(curl -fsS -X POST "$BASE/connect/init?return=%2Fsmoke%3Fok%3D1")
echo "$INIT" | jq .
NONCE=$(echo "$INIT" | jq -r .nonce)
STATUS_URL=$(echo "$INIT" | jq -r .status_url)
FINISH_URL=$(echo "$INIT" | jq -r .finish_url)

if [[ "${MOCK:-0}" == "1" ]]; then
    AID="${USER_AID:?USER_AID is required in MOCK mode}"
    OOBI="[{\"eid\":\"BW\",\"scheme\":\"http\",\"url\":\"http://w/\"},{\"cid\":\"$AID\",\"role\":\"witness\",\"eid\":\"BW\"}]"
    PAYLOAD=$(jq -nc --arg nonce "$NONCE" --arg aid "$AID" \
        '{v:"cyfron-sp-auth/1", nonce:$nonce, entity_aid:$aid, disclosed_attributes:{}, tos_hash:null}')
    SIGNED="${PAYLOAD}-MOCK:${AID}"
else
    if [[ -n "${CYFRON_ENDPOINT_FILE:-}" ]]; then
        CYFRON_URL=$(jq -r .url "$CYFRON_ENDPOINT_FILE")
        CYFRON_TOKEN=$(jq -r .token "$CYFRON_ENDPOINT_FILE")
    fi
    : "${CYFRON_URL:?CYFRON_URL (or CYFRON_ENDPOINT_FILE) is required}"
    : "${CYFRON_TOKEN:?CYFRON_TOKEN is required}"
    ALIAS="${USER_ALIAS:-smoke-user}"
    # Defaults live in their own variables: a `}` inside a ${var:-default}
    # word ends the expansion early and truncates the JSON.
    DEFAULT_WITNESS='{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.dkms.colossi.network/"}'
    DEFAULT_WATCHER='{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.dkms.colossi.network/"}'
    WITNESS_LOCATION="${WITNESS_LOCATION:-$DEFAULT_WITNESS}"
    WATCHER_LOCATION="${WATCHER_LOCATION:-$DEFAULT_WATCHER}"
    H=(-H "Authorization: Bearer $CYFRON_TOKEN" -H "Content-Type: application/json")
    # Aliases on the daemon are "<name>-<8 hex>", so look the name up first.
    INFO=$(curl -sS "${H[@]}" "$CYFRON_URL/identifiers" | jq -c --arg n "$ALIAS" '[.[] | select(.name == $n or .alias == $n)][0] // empty')
    if [[ -z "$INFO" ]]; then
        echo "-> creating identity '$ALIAS' on $CYFRON_URL (takes a while with real witnesses)"
        CREATED=$(curl -fsS "${H[@]}" -X POST "$CYFRON_URL/identifiers" \
            -d "$(jq -nc --arg n "$ALIAS" --arg w "$WITNESS_LOCATION" --arg wa "$WATCHER_LOCATION" \
                '{name:$n, description:"dauthz-gate smoke user", witness_urls:[$w], watcher_url:$wa}')")
        ALIAS=$(echo "$CREATED" | jq -r .alias)
    else
        ALIAS=$(echo "$INFO" | jq -r .alias)
    fi
    INFO=$(curl -fsS "${H[@]}" "$CYFRON_URL/keri/identifier-by-alias?alias=$ALIAS")
    AID=$(echo "$INFO" | jq -r .aid)
    OOBI=$(echo "$INFO" | jq -c .oobi)
    if [[ -n "${PRESENT_FILE:-}" && "${PRESENT_MODE:-inline}" == "inline" ]]; then
        PRESENT_SAID=$(jq -r .said "$PRESENT_FILE")
        PAYLOAD=$(jq -nc --arg nonce "$NONCE" --arg aid "$AID" --arg said "$PRESENT_SAID" \
            '{v:"cyfron-sp-auth/2", nonce:$nonce, entity_aid:$aid, disclosed_attributes:{}, tos_hash:null, presented_credential_said:$said}')
        echo "-> presenting credential $PRESENT_SAID"
    else
        PAYLOAD=$(jq -nc --arg nonce "$NONCE" --arg aid "$AID" \
            '{v:"cyfron-sp-auth/1", nonce:$nonce, entity_aid:$aid, disclosed_attributes:{}, tos_hash:null}')
    fi
    echo "-> signing as $ALIAS ($AID)"
    SIGNED=$(curl -fsS "${H[@]}" -X POST "$CYFRON_URL/keri/sign-cesr" \
        -d "$(jq -nc --arg a "$ALIAS" --arg p "$PAYLOAD" '{alias:$a, payload:$p}')" | jq -r .cesr)
fi

BODY=$(jq -nc --arg nonce "$NONCE" --arg oobi "$OOBI" --arg signed "$SIGNED" \
    '{nonce:$nonce, entity_oobi:$oobi, signed_challenge:$signed, disclosed_attributes:{}, tos_hash:null, decision:"approve"}')
if [[ -n "${PRESENT_FILE:-}" && "${PRESENT_MODE:-inline}" == "inline" ]]; then
    BODY=$(echo "$BODY" | jq -c --slurpfile p "$PRESENT_FILE" '. + {presented_credential: {acdc: $p[0].acdc, issuer_cesr: $p[0].issuer_cesr, disclosed: []}}')
fi
echo "-> POST $BASE/connect/callback (aid=$AID)"
CB_CODE=$(curl -sS -o /tmp/dauthz-smoke-cb.json -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "$BODY" "$BASE/connect/callback")
cat /tmp/dauthz-smoke-cb.json; echo
if [[ "${EXPECT_DENY:-0}" == "1" ]]; then
    [[ "$CB_CODE" == "403" ]] && { echo "-> ✓ callback refused as expected"; exit 0; }
    echo "ERROR: expected 403, got $CB_CODE" >&2; exit 1
fi
[[ "$CB_CODE" == "200" ]] || { echo "ERROR: callback returned $CB_CODE" >&2; exit 1; }

echo "-> GET $SITE_URL$STATUS_URL"
STATUS=$(curl -fsS "$SITE_URL$STATUS_URL"); echo "$STATUS" | jq .
TOKEN=$(echo "$STATUS" | jq -r '.handoff_token // empty')
[[ -n "$TOKEN" ]] || { echo "ERROR: no handoff token" >&2; exit 1; }

JAR=$(mktemp)
echo "-> GET $SITE_URL$FINISH_URL?token=…"
LOC=$(curl -sS -c "$JAR" -o /dev/null -w '%{redirect_url}' "$SITE_URL$FINISH_URL?token=$TOKEN")
echo "   redirect -> $LOC"
grep -q dauthz_session "$JAR" || { echo "ERROR: no session cookie set" >&2; exit 1; }

echo "-> replaying the handoff token must fail"
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "$SITE_URL$FINISH_URL?token=$TOKEN")" == "403" ]] || { echo "ERROR: replay accepted" >&2; exit 1; }

# /dauthz/auth is `internal` behind nginx, so probe the session through
# /dauthz/whoami (same cookie, same decision) and then fetch a protected page.
WHO=$(curl -sS -b "$JAR" "$BASE/whoami")
NOAUTH=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/whoami")
echo "-> whoami with cookie: $WHO"
echo "-> whoami without cookie: HTTP $NOAUTH"
[[ "$NOAUTH" == "401" ]] || { echo "ERROR: whoami without a cookie must be 401" >&2; exit 1; }
if echo "$WHO" | jq -e '.authorized == true' >/dev/null; then
    ROOT=$(curl -sS -b "$JAR" -o /dev/null -w '%{http_code}' "$SITE_URL/")
    ANON=$(curl -sS -o /dev/null -w '%{http_code}' "$SITE_URL/")
    echo "-> GET / with cookie: $ROOT, without: $ANON  (404/404 means the gate is reached without nginx)"
    if [[ "$ROOT" == "200" && "$ANON" == "302" ]] || [[ "$ROOT" == "404" && "$ANON" == "404" ]]; then
        echo "-> ✓ session established for $AID"
    else
        echo "ERROR: unexpected access decision on /" >&2; exit 1
    fi
elif echo "$STATUS" | jq -e '.needs_credential == true' >/dev/null; then
    ROOT=$(curl -sS -b "$JAR" -o /dev/null -w '%{http_code} %{redirect_url}' "$SITE_URL/")
    echo "-> GET / with cookie: $ROOT"
    echo "-> ✓ signed in; policy still needs a credential (present it at $GATE_PREFIX/present)"
    if [[ -n "${PRESENT_FILE:-}" && "${PRESENT_MODE:-inline}" == "page" ]]; then
        # What a user pastes: the wallet's Present output, {acdc, issuer_cesr, disclosed}.
        PROOF=$(jq -c '{acdc, issuer_cesr, disclosed: []}' "$PRESENT_FILE")
        echo "-> POST $BASE/present (pasting the proof)"
        PAGE_CODE=$(curl -sS -b "$JAR" -c "$JAR" -o /tmp/dauthz-smoke-present.html -w '%{http_code}' \
            --data-urlencode "return=/smoke?page=1" --data-urlencode "proof=$PROOF" "$BASE/present")
        if [[ "${EXPECT_DENY:-0}" == "1" ]]; then
            [[ "$PAGE_CODE" == "200" ]] && grep -q 'class="status error"' /tmp/dauthz-smoke-present.html \
                && { echo "-> ✓ presentation refused as expected: $(grep -o '<div class="status error">[^<]*' /tmp/dauthz-smoke-present.html | sed 's/.*>//')"; rm -f "$JAR"; exit 0; }
            echo "ERROR: expected the page to refuse the proof (got $PAGE_CODE)" >&2; exit 1
        fi
        [[ "$PAGE_CODE" == "302" ]] || { echo "ERROR: /present returned $PAGE_CODE: $(grep -o '<div class="status error">[^<]*' /tmp/dauthz-smoke-present.html)" >&2; exit 1; }
        WHO=$(curl -sS -b "$JAR" "$BASE/whoami")
        echo "-> whoami after presenting: $WHO"
        echo "$WHO" | jq -e '.authorized == true and .cred_said != null' >/dev/null || { echo "ERROR: session not upgraded" >&2; exit 1; }
        ROOT=$(curl -sS -b "$JAR" -o /dev/null -w '%{http_code}' "$SITE_URL/")
        echo "-> GET / with upgraded cookie: $ROOT"
        [[ "$ROOT" == "200" || "$ROOT" == "404" ]] || { echo "ERROR: unexpected access decision on /" >&2; exit 1; }
        echo "-> ✓ credential presented on the page"
    fi
else
    echo "ERROR: unexpected auth decision" >&2; exit 1
fi
rm -f "$JAR"
