#!/usr/bin/env bash
# Play the consortium authority on the user-cyfron daemon:
#   - ensure the user identity ("alice") and the authority identity exist,
#   - create a governance, add the OCA repository, pull the passport schema,
#   - issue a passport credential to alice (signed + TEL-anchored),
#   - write .env.policy so the gate runs in credential mode for that issuer.
# Idempotent: re-running reuses what exists and issues a fresh credential.
#
# Env: CYFRON_URL, CYFRON_TOKEN (user daemon), WITNESS_LOCATION, WATCHER_LOCATION,
#      SCHEMA_SAID (OCA bundle), OCA_REPO_URL, USER_ALIAS (alice), AUTHORITY_ALIAS,
#      OUT (state/passport.json), POLICY_FILE (.env.policy)
set -euo pipefail
: "${CYFRON_URL:?}" "${CYFRON_TOKEN:?}" "${WITNESS_LOCATION:?}" "${WATCHER_LOCATION:?}"
SCHEMA_SAID="${SCHEMA_SAID:-ELoHlOIHQQ3vkA-erKdD5ab9w9eij2Y4hjoYox6cS7wu}"
OCA_REPO_URL="${OCA_REPO_URL:-https://repository.oca.argo.colossi.network}"
USER_ALIAS="${USER_ALIAS:-alice}"
AUTHORITY_ALIAS="${AUTHORITY_ALIAS:-authority}"
OUT="${OUT:-state/passport.json}"
POLICY_FILE="${POLICY_FILE:-.env.policy}"
H=(-H "Authorization: Bearer $CYFRON_TOKEN" -H "Content-Type: application/json")

ensure_identity() {  # name -> alias
    local name="$1" info
    info=$(curl -fsS "${H[@]}" "$CYFRON_URL/identifiers" | jq -c --arg n "$name" '[.[] | select(.name == $n or .alias == $n)][0] // empty')
    if [[ -z "$info" ]]; then
        echo "-> creating identity '$name' (contacts the witness; may take a while)" >&2
        info=$(curl -fsS "${H[@]}" -X POST "$CYFRON_URL/identifiers" \
            -d "$(jq -nc --arg n "$name" --arg w "$WITNESS_LOCATION" --arg wa "$WATCHER_LOCATION" \
                '{name:$n, description:"dauthz-gate sandbox", witness_urls:[$w], watcher_url:$wa}')")
    fi
    echo "$info" | jq -r .alias
}

USER_A=$(ensure_identity "$USER_ALIAS")
AUTH_A=$(ensure_identity "$AUTHORITY_ALIAS")
USER_AID=$(curl -fsS "${H[@]}" "$CYFRON_URL/keri/identifier-by-alias?alias=$USER_A" | jq -r .aid)
AUTH_INFO=$(curl -fsS "${H[@]}" "$CYFRON_URL/keri/identifier-by-alias?alias=$AUTH_A")
AUTH_AID=$(echo "$AUTH_INFO" | jq -r .aid)
AUTH_OOBI=$(echo "$AUTH_INFO" | jq -c .oobi)
echo "-> user $USER_A = $USER_AID"
echo "-> authority $AUTH_A = $AUTH_AID"

GOV_ID=$(curl -fsS "${H[@]}" "$CYFRON_URL/governance" | jq -r '[.[] | select(.name == "NextGen Consortium")][0].id // empty')
if [[ -z "$GOV_ID" ]]; then
    echo "-> creating governance"
    GOV_ID=$(curl -fsS "${H[@]}" -X POST "$CYFRON_URL/governance" \
        -d '{"name":"NextGen Consortium","description":"Issues research passports (sandbox)"}' | jq -r .id)
fi
# There is no GET /governance/{id}; read the template back from the list.
GOV=$(curl -fsS "${H[@]}" "$CYFRON_URL/governance" | jq -c --arg id "$GOV_ID" '[.[] | select(.id == $id)][0]')
REPO_ID=$(echo "$GOV" | jq -r --arg u "$OCA_REPO_URL" '[.oca_repositories[] | select(.url == $u)][0].id // empty')
if [[ -z "$REPO_ID" ]]; then
    echo "-> adding OCA repository $OCA_REPO_URL"
    REPO_ID=$(curl -fsS "${H[@]}" -X POST "$CYFRON_URL/governance/$GOV_ID/oca-repositories" \
        -d "$(jq -nc --arg u "$OCA_REPO_URL" '{url:$u, name:"Colossi OCA repository"}')" | jq -r .id)
fi
SCHEMA_ID=$(echo "$GOV" | jq -r --arg s "$SCHEMA_SAID" '[.oca_schemas[] | select(.said == $s)][0].id // empty')
if [[ -z "$SCHEMA_ID" ]]; then
    echo "-> pulling OCA schema $SCHEMA_SAID"
    SCHEMA_ID=$(curl -fsS "${H[@]}" -X POST "$CYFRON_URL/governance/$GOV_ID/oca-schemas" \
        -d "$(jq -nc --arg s "$SCHEMA_SAID" --arg r "$REPO_ID" '{said:$s, repository_id:$r}')" | jq -r .id)
fi
echo "-> governance $GOV_ID, schema $SCHEMA_ID"

echo "-> issuing passport to $USER_AID (signs, anchors in the authority's TEL)"
ISSUED=$(curl -fsS "${H[@]}" -X POST "$CYFRON_URL/governance/$GOV_ID/issue" \
    -d "$(jq -nc --arg i "$AUTH_AID" --arg r "$USER_AID" --arg s "$SCHEMA_ID" \
        '{issuer_aid:$i, recipient_name:"Alice Researcher", recipient_aid:$r, schema_id:$s,
          attributes:{full_name:"Alice Researcher", organization:"NextGen", job_title:"Researcher"},
          validity:{kind:"months", months:12}, note:"sandbox passport"}')")
mkdir -p "$(dirname "$OUT")"
echo "$ISSUED" | jq --arg gov "$GOV_ID" '{said, acdc, issuer_cesr, schema_said, subject_aid, issuer_aid, expires_at, tel_status, delivery_status, governance_id: $gov}' > "$OUT"
echo "-> passport $(jq -r .said "$OUT") written to $OUT (delivery: $(jq -r .delivery_status "$OUT"))"

cat > "$POLICY_FILE" <<POL
DAUTHZ_POLICY__MODE=credential
DAUTHZ_POLICY__SCHEMA_SAID=$SCHEMA_SAID
DAUTHZ_POLICY__ISSUER_AID=$AUTH_AID
DAUTHZ_POLICY__ISSUER_OOBI=$AUTH_OOBI
DAUTHZ_POLICY__REVOCATION_CHECK=if_known
DAUTHZ_POLICY__PRESENTATION=both
DAUTHZ_POLICY__REQUIREMENT_TEXT=Requires a NextGen Research Passport issued by the sandbox authority.
POL
echo "-> $POLICY_FILE now selects credential mode for issuer $AUTH_AID; restart the gate (make restart-gate)"
