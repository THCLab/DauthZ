#!/usr/bin/env bash
# Issue the demo "passport" credential and write the gate policy that
# requires it. Run from the repository root.
#
#   dauthz-demo/passport.sh ["Full Name"] [NATIONALITY]
#
# An authority identifier (created on first run) issues a passport to the
# holder; dkms anchors the issuance in the authority's registry and signs
# the credential, so the gate can check it without asking the authority.
# Outputs, under target/dauthz-demo/:
#   passport.json  the proof the holder presents: {said, acdc, issuer_cesr}
#   passport.env   DAUTHZ_POLICY__* settings for dauthz-gate (credential mode)
#
# Env: DKMS_BINARY (default dkms), AUTHORITY (default demo-authority),
#      HOLDER (default demo-entity), WITNESS_URLS (space separated),
#      WATCHER_URL, OUT (default target/dauthz-demo)

set -euo pipefail
cd "$(dirname "$0")/.."
DKMS="${DKMS_BINARY:-dkms}"
AUTHORITY="${AUTHORITY:-demo-authority}"
HOLDER="${HOLDER:-demo-entity}"
WITNESS_URLS="${WITNESS_URLS:-http://172.17.0.1:3232 http://172.17.0.1:3233}"
WATCHER_URL="${WATCHER_URL:-http://172.17.0.1:3235}"
OUT="${OUT:-target/dauthz-demo}"
FULL_NAME="${1:-Ada Lovelace}"
NATIONALITY="${2:-GB}"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
"$DKMS" auth --help >/dev/null 2>&1 || {
    echo "'$DKMS' is not a dkms-bin with 'auth' commands; set DKMS_BINARY" >&2; exit 1; }

aid_of() { "$DKMS" identifier list --json | jq -r --arg a "$1" '.[] | select(.alias == $a) | .aid'; }

HOLDER_AID=$(aid_of "$HOLDER")
[[ -n "$HOLDER_AID" ]] || { echo "holder '$HOLDER' does not exist; create it first (dkms identifier init -a $HOLDER ...)" >&2; exit 1; }

if [[ -z "$(aid_of "$AUTHORITY")" ]]; then
    echo "-> creating the passport authority '$AUTHORITY'"
    args=()
    for w in $WITNESS_URLS; do args+=(--witness-url "$w"); done
    "$DKMS" identifier init -a "$AUTHORITY" "${args[@]}" --watcher-url "$WATCHER_URL"
    echo
fi
AUTHORITY_AID=$(aid_of "$AUTHORITY")

# The schema is identified by the SAID of passport.schema.json.
SCHEMA_SAID=$("$DKMS" said sad -j "$(cat dauthz-demo/passport.schema.json)" | jq -r .d)

mkdir -p "$OUT"
echo "-> $AUTHORITY issues a passport to $HOLDER ($HOLDER_AID)"
"$DKMS" data issue -a "$AUTHORITY" --holder "$HOLDER_AID" --proof -b "$SCHEMA_SAID" \
    -m "$(jq -nc --arg n "$FULL_NAME" --arg c "$NATIONALITY" '{full_name: $n, nationality: $c}')" \
    > "$OUT/passport.json"
jq . "$OUT/passport.json" > /dev/null

ISSUER_OOBI=$("$DKMS" identifier oobi get -a "$AUTHORITY")
cat > "$OUT/passport.env" <<ENV
DAUTHZ_POLICY__MODE=credential
DAUTHZ_POLICY__SCHEMA_SAID=$SCHEMA_SAID
DAUTHZ_POLICY__ISSUER_AID=$AUTHORITY_AID
DAUTHZ_POLICY__ISSUER_OOBI='$ISSUER_OOBI'
DAUTHZ_POLICY__PRESENTATION=both
DAUTHZ_POLICY__REVOCATION_CHECK=if_known
DAUTHZ_POLICY__REQUIREMENT_TEXT='Access requires a DAuthZ demo passport issued by $AUTHORITY.'
ENV

cat <<DONE

Passport $(jq -r .said "$OUT/passport.json") issued to $HOLDER.
  proof:  $OUT/passport.json
  policy: $OUT/passport.env

Restart the gate with the passport policy:
  (set -a; . $OUT/passport.env; set +a; cargo run -p dauthz-gate -- --config dauthz-demo/gate.demo.toml serve)

Then sign in presenting the passport:
  dkms auth respond -a $HOLDER --present $OUT/passport.json '<cyfron://auth link>'
DONE
