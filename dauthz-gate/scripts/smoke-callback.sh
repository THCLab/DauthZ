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
    H=(-H "Authorization: Bearer $CYFRON_TOKEN" -H "Content-Type: application/json")
    INFO=$(curl -sS "${H[@]}" "$CYFRON_URL/keri/identifier-by-alias?alias=$ALIAS" || true)
    if ! echo "$INFO" | jq -e .aid >/dev/null 2>&1; then
        echo "-> creating identity '$ALIAS' on $CYFRON_URL (takes a while with real witnesses)"
        CREATED=$(curl -fsS "${H[@]}" -X POST "$CYFRON_URL/identifiers" \
            -d "$(jq -nc --arg n "$ALIAS" '{name:$n, description:"dauthz-gate smoke user"}')")
        ALIAS=$(echo "$CREATED" | jq -r .alias)
        INFO=$(curl -fsS "${H[@]}" "$CYFRON_URL/keri/identifier-by-alias?alias=$ALIAS")
    fi
    AID=$(echo "$INFO" | jq -r .aid)
    OOBI=$(echo "$INFO" | jq -c .oobi)
    PAYLOAD=$(jq -nc --arg nonce "$NONCE" --arg aid "$AID" \
        '{v:"cyfron-sp-auth/1", nonce:$nonce, entity_aid:$aid, disclosed_attributes:{}, tos_hash:null}')
    echo "-> signing as $ALIAS ($AID)"
    SIGNED=$(curl -fsS "${H[@]}" -X POST "$CYFRON_URL/keri/sign-cesr" \
        -d "$(jq -nc --arg a "$ALIAS" --arg p "$PAYLOAD" '{alias:$a, payload:$p}')" | jq -r .cesr)
fi

BODY=$(jq -nc --arg nonce "$NONCE" --arg oobi "$OOBI" --arg signed "$SIGNED" \
    '{nonce:$nonce, entity_oobi:$oobi, signed_challenge:$signed, disclosed_attributes:{}, tos_hash:null, decision:"approve"}')
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

AUTH=$(curl -sS -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE/auth")
NOAUTH=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/auth")
echo "-> /auth with cookie: $AUTH, without: $NOAUTH"
if [[ "$AUTH" == "204" && "$NOAUTH" == "401" ]]; then
    echo "-> ✓ session established for $AID"
elif [[ "$AUTH" == "401" ]] && echo "$STATUS" | jq -e '.needs_credential == true' >/dev/null; then
    echo "-> ✓ signed in; policy still needs a credential (present it at $GATE_PREFIX/present)"
else
    echo "ERROR: unexpected auth decision" >&2; exit 1
fi
ROOT=$(curl -sS -b "$JAR" -o /dev/null -w '%{http_code}' "$SITE_URL/")
echo "-> GET / with cookie: $ROOT"
rm -f "$JAR"
