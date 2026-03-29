// ---------------------------------------------------------------------------
// State: window.wasm, window.serviceState, etc. set in index.html module script
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
function log(msg) {
    const el = document.getElementById('log-entries');
    const ts = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.textContent = `[${ts}] ${msg}`;
    el.prepend(entry);
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------
function switchTab(name) {
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelector(`.tab[data-tab="${name}"]`).classList.add('active');
    document.getElementById('panel-' + name).classList.add('active');
}

document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

// ---------------------------------------------------------------------------
// Copy-to-clipboard
// ---------------------------------------------------------------------------
document.querySelectorAll('[data-copy]').forEach(el => {
    el.addEventListener('click', () => {
        navigator.clipboard.writeText(el.textContent.trim()).then(() => {
            el.classList.add('copied');
            setTimeout(() => el.classList.remove('copied'), 1200);
        });
    });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function $(id) { return document.getElementById(id); }
function show(id) { $(id).classList.remove('hidden'); }
function hide(id) { $(id).classList.add('hidden'); }

function parseAid(text) {
    text = text.trim();
    try {
        const obj = JSON.parse(text);
        return obj.aid || obj.prefix || text;
    } catch { return text; }
}

function showError(id, msg) {
    const el = $(id);
    el.textContent = 'ERROR: ' + msg;
    el.classList.remove('hidden');
    el.classList.add('error');
}

// ---------------------------------------------------------------------------
// SERVICE STEPS — Setup
// ---------------------------------------------------------------------------

function saveServiceAid() {
    const val = $('svc-aid-input').value.trim();
    if (!val) return;
    window.svcAid = parseAid(val);
    log('Service AID saved: ' + window.svcAid);
    show('svc-step-2');
}

function saveServiceOobi() {
    const val = $('svc-oobi-input').value.trim();
    if (!val) return;
    try {
        window.svcOobi = JSON.parse(val);
        log('Service OOBI saved');
        show('svc-step-3');
        const oobiDisplay = Array.isArray(window.svcOobi)
            ? window.svcOobi[0] : window.svcOobi;
        $('svc-info').textContent = 'AID: ' + window.svcAid
            + '\nOOBI: ' + JSON.stringify(oobiDisplay, null, 2);
    } catch (e) {
        alert('Invalid JSON: ' + e.message);
    }
}

function initServiceSdk() {
    const oobiStr = typeof window.svcOobi === 'string'
        ? window.svcOobi
        : JSON.stringify(window.svcOobi[0] || window.svcOobi);
    window.serviceState = new window.wasm.DauthzService(window.svcAid, oobiStr);
    log('Service SDK initialized');
    show('svc-step-4');
    show('svc-step-accounts');
    listAccounts();
}

// ---------------------------------------------------------------------------
// SERVICE STEPS — Resolve Entity OOBI
// ---------------------------------------------------------------------------

function resolveEntityOobi() {
    const val = $('entity-oobi-input').value.trim();
    if (!val) return;
    try {
        const entityOobi = JSON.parse(val);
        const firstOobi = Array.isArray(entityOobi) ? entityOobi[0] : entityOobi;
        const oobiFile = JSON.stringify({ oobi: firstOobi.url || firstOobi }, null, 2);

        const resolveCmd =
            `echo '${oobiFile}' > /tmp/dauthz-oobi/entity.json && ` +
            `dkms identifier oobi resolve -a demo-service -f /tmp/dauthz-oobi/entity.json`;
        $('resolve-entity-cmd').textContent = resolveCmd;
        show('resolve-entity-cmd');

        log('Entity OOBI ready to resolve');
        // After user confirms they ran the command, proceed
        show('svc-step-5');
    } catch (e) {
        alert('Invalid JSON: ' + e.message);
    }
}

// ---------------------------------------------------------------------------
// SERVICE STEPS — Challenge ceremonies
// ---------------------------------------------------------------------------

function issueChallenge(purpose) {
    if (!window.serviceState) return;
    try {
        const challenge = window.serviceState.create_challenge(purpose);
        window.currentChallenge = challenge;
        const json = challenge.to_json();
        const outId = purpose === 'registration'
            ? 'reg-challenge-output'
            : 'login-challenge-output';
        $(outId).textContent = JSON.stringify(json, null, 2);
        show(outId);

        const transferId = purpose === 'registration'
            ? 'reg-challenge-transfer'
            : 'login-challenge-transfer';
        show(transferId);

        window.clipboard.challengeJson = JSON.stringify(json, null, 2);
        log(`${purpose} challenge issued: nonce=${json.nonce}`);

        if (purpose === 'registration') {
            show('svc-step-6');
        } else {
            show('svc-step-8');
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

function prepareVerifySignature(purpose) {
    const inputId = purpose === 'registration'
        ? 'entity-response-input'
        : 'login-response-input';
    const val = $(inputId).value.trim();
    if (!val) return;
    try {
        const respJson = JSON.parse(val);

        // For login: validate nonce matches the issued challenge and check expiry
        if (purpose === 'identification' && window.currentChallenge) {
            const challengeJson = window.currentChallenge.to_json();
            const checkEl = $('login-nonce-check');

            // Nonce mismatch
            if (respJson.nonce !== challengeJson.nonce) {
                checkEl.textContent = 'REJECTED: Response nonce does not match the issued challenge.\n' +
                    'Expected: ' + challengeJson.nonce + '\n' +
                    'Got: ' + respJson.nonce;
                checkEl.classList.remove('hidden');
                checkEl.classList.add('error');
                log('Login rejected: nonce mismatch');
                return;
            }

            // Challenge expired
            const exp = new Date(challengeJson.expires_at);
            if (isNaN(exp.getTime()) || new Date() > exp) {
                checkEl.textContent = 'REJECTED: Challenge has expired.\n' +
                    'Expired at: ' + challengeJson.expires_at;
                checkEl.classList.remove('hidden');
                checkEl.classList.add('error');
                log('Login rejected: challenge expired');
                return;
            }

            // AID mismatch
            if (respJson.entity_aid) {
                const account = window.serviceState.list_accounts();
                const known = Array.isArray(account) && account.some(a => a.aid === respJson.entity_aid);
                if (!known) {
                    checkEl.textContent = 'REJECTED: Entity AID is not registered.\n' +
                        'AID: ' + respJson.entity_aid;
                    checkEl.classList.remove('hidden');
                    checkEl.classList.add('error');
                    log('Login rejected: unknown AID ' + respJson.entity_aid);
                    return;
                }
            }

            checkEl.textContent = 'PASSED: Nonce matches, challenge is fresh, AID is registered.\n' +
                'Nonce: ' + respJson.nonce + '\n' +
                'Expires: ' + challengeJson.expires_at;
            checkEl.classList.remove('hidden', 'error');
            log('Login pre-check passed');
        }

        // Store parsed response for later use
        window._pendingResponse = respJson;

        const escaped = respJson.signed_challenge.replace(/'/g, "'\\''");
        const oobiEscaped = respJson.entity_oobi.replace(/'/g, "'\\''");
        const verifyCmd = `dkms data verify -a demo-service -m '${escaped}' -o '${oobiEscaped}'`;

        const areaId = purpose === 'registration'
            ? 'reg-verify-sig-area'
            : 'login-verify-sig-area';
        const cmdId = purpose === 'registration'
            ? 'reg-verify-cmd'
            : 'login-verify-cmd';
        $(cmdId).textContent = verifyCmd;
        // Re-attach click-to-copy for the newly created element
        $(cmdId).addEventListener('click', () => {
            navigator.clipboard.writeText($(cmdId).textContent.trim()).then(() => {
                $(cmdId).classList.add('copied');
                setTimeout(() => $(cmdId).classList.remove('copied'), 1200);
            });
        });
        show(areaId);
        log('Verify signature command prepared (' + purpose + ')');
    } catch (e) {
        alert('Invalid response JSON: ' + e.message);
    }
}

function verifyRegistration(verified) {
    if (!window.serviceState || !window.currentChallenge || !window._pendingResponse) return;
    try {
        const respJson = window._pendingResponse;
        const response = new window.wasm.JsChallengeResponse(
            respJson.entity_aid,
            respJson.entity_oobi,
            respJson.nonce,
            respJson.signed_challenge,
        );
        const result = window.serviceState.handle_response(response, verified);
        const el = $('reg-result');
        el.textContent = `Kind: ${result.kind}\nAID: ${result.aid}\nAccount ID: ${result.account_id}`;
        if (result.session_token) el.textContent += '\nSession Token: ' + result.session_token;
        if (result.reason) el.textContent += '\nReason: ' + result.reason;
        el.classList.remove('hidden', 'error');
        log('Registration result: ' + result.kind);

        if (result.kind === 'registered') {
            show('svc-step-7');
            listAccounts();
        }
    } catch (e) {
        showError('reg-result', e.message);
        log('Registration error: ' + e.message);
    }
}

function verifyLogin(verified) {
    if (!window.serviceState || !window._pendingResponse) return;
    try {
        const respJson = window._pendingResponse;
        const response = new window.wasm.JsChallengeResponse(
            respJson.entity_aid,
            respJson.entity_oobi,
            respJson.nonce,
            respJson.signed_challenge,
        );
        const result = window.serviceState.handle_response(response, verified);
        const el = $('login-result');
        el.textContent = `Kind: ${result.kind}\nAID: ${result.aid}\nAccount ID: ${result.account_id}`;
        if (result.session_token) el.textContent += '\nSession Token: ' + result.session_token;
        if (result.reason) el.textContent += '\nReason: ' + result.reason;
        el.classList.remove('hidden', 'error');
        log('Login result: ' + result.kind);

        if (result.kind === 'authenticated') {
            show('svc-step-sessions');
            listSessions();
        }
    } catch (e) {
        showError('login-result', e.message);
        log('Login error: ' + e.message);
    }
}

function listAccounts() {
    if (!window.serviceState) return;
    try {
        const accounts = window.serviceState.list_accounts();
        $('accounts-list').textContent = JSON.stringify(accounts, null, 2);
    } catch (e) {
        $('accounts-list').textContent = 'Error: ' + e.message;
    }
}

function listSessions() {
    if (!window.serviceState) return;
    try {
        const sessions = window.serviceState.list_sessions();
        const container = $('sessions-list');
        container.innerHTML = '';

        if (!Array.isArray(sessions) || sessions.length === 0) {
            container.innerHTML = '<p class="hint">No active sessions.</p>';
            return;
        }

        sessions.forEach(s => {
            const card = document.createElement('div');
            card.className = 'session-card';

            const status = s.invalidated ? 'invalidated' : 'valid';
            const statusClass = s.invalidated ? 'session-invalidated' : 'session-valid';

            card.innerHTML =
                `<div class="session-header">` +
                `<span class="session-aid">${s.aid}</span>` +
                `<span class="session-status ${statusClass}">${status}</span>` +
                `</div>` +
                `<div class="session-details">` +
                `<div>Token: <code>${s.token.substring(0, 8)}...</code></div>` +
                `<div>Account: ${s.account_id.substring(0, 8)}...</div>` +
                `<div>Created: ${s.created_at}</div>` +
                `<div>Expires: ${s.expires_at}</div>` +
                `</div>`;

            if (!s.invalidated) {
                card.innerHTML += `<button class="danger" onclick="logoutSession('${s.token}')">Logout (Invalidate Token)</button>`;
            }

            container.appendChild(card);
        });
    } catch (e) {
        $('sessions-list').innerHTML = '<p class="hint">Error: ' + e.message + '</p>';
    }
}

async function logoutSession(token) {
    if (!window.serviceState) return;
    try {
        const invalidated = window.serviceState.invalidate_session(token);
        if (invalidated) {
            log('Session invalidated: ' + token.substring(0, 8) + '...');
            // Verify it's actually invalidated
            const check = window.serviceState.verify_session(token);
            log('Session verification after logout: ' + JSON.stringify(check));
        } else {
            log('Session not found: ' + token.substring(0, 8) + '...');
        }
        listSessions();
    } catch (e) {
        log('Logout error: ' + e.message);
    }
}

// ---------------------------------------------------------------------------
// SERVICE → ENTITY transfer
// ---------------------------------------------------------------------------

function sendChallengeToEntity() {
    const json = window.clipboard.challengeJson;
    if (!json) return;

    // Reset entity ceremony steps
    hide('ent-step-4');
    hide('ent-step-5');
    hide('response-output');
    $('response-output').textContent = '';
    hide('response-transfer');
    $('signed-output').value = '';
    hide('challenge-info');

    // Switch to entity tab, auto-fill challenge
    switchTab('entity');
    $('challenge-input').value = json;

    show('challenge-auto-area');
    hide('challenge-manual-area');

    const chObj = JSON.parse(json);
    $('challenge-auto-info').innerHTML =
        '<div class="payload">' + json + '</div>' +
        '<p><strong>Nonce:</strong> ' + chObj.nonce + '<br>' +
        '<strong>Service AID:</strong> ' + chObj.service_aid + '<br>' +
        '<strong>Purpose:</strong> ' + chObj.purpose + '<br>' +
        '<strong>Expires:</strong> ' + chObj.expires_at + '</p>';

    show('ent-step-4');
    log('Challenge sent to Entity tab (purpose=' + chObj.purpose + ')');
}

// ---------------------------------------------------------------------------
// ENTITY STEPS — Setup
// ---------------------------------------------------------------------------

function saveEntityAid() {
    const val = $('ent-aid-input').value.trim();
    if (!val) return;
    window.entityState.aid = parseAid(val);
    log('Entity AID saved: ' + window.entityState.aid);
    show('ent-step-2');
}

function saveEntityOobi() {
    const val = $('ent-oobi-input').value.trim();
    if (!val) return;
    try {
        window.entityState.oobi = JSON.parse(val);
        log('Entity OOBI saved');
        show('ent-step-3');
    } catch (e) {
        alert('Invalid JSON: ' + e.message);
    }
}

function resolveServiceOobiSetup() {
    const val = $('svc-oobi-resolve-input').value.trim();
    if (!val) return;
    try {
        const svcOobi = JSON.parse(val);
        const firstOobi = Array.isArray(svcOobi) ? svcOobi[0] : svcOobi;
        const oobiFile = JSON.stringify({ oobi: firstOobi.url || firstOobi }, null, 2);

        const resolveCmd =
            `echo '${oobiFile}' > /tmp/dauthz-oobi/service.json && ` +
            `dkms identifier oobi resolve -a demo-entity -f /tmp/dauthz-oobi/service.json`;
        $('resolve-svc-cmd').textContent = resolveCmd;
        show('resolve-svc-cmd');

        log('Service OOBI ready to resolve');
        show('ent-step-4');
    } catch (e) {
        alert('Invalid JSON: ' + e.message);
    }
}

// ---------------------------------------------------------------------------
// ENTITY STEPS — Challenge ceremony
// ---------------------------------------------------------------------------

function acceptAutoChallenge() {
    const json = $('challenge-input').value;
    if (!json) return;
    processReceivedChallenge(JSON.parse(json));
}

function receiveChallenge() {
    const val = $('challenge-input').value.trim();
    if (!val) return;
    try {
        processReceivedChallenge(JSON.parse(val));
    } catch (e) {
        alert('Invalid challenge JSON: ' + e.message);
    }
}

function processReceivedChallenge(chObj) {
    window.receivedChallenge = chObj;

    $('challenge-info').textContent =
        `Nonce: ${chObj.nonce}\nService AID: ${chObj.service_aid}\n` +
        `Purpose: ${chObj.purpose}\nExpires: ${chObj.expires_at}`;
    show('challenge-info');

    show('ent-step-5');

    // Prepare sign command
    const challengeStr = JSON.stringify(chObj);
    const escaped = challengeStr.replace(/'/g, "'\\''");
    $('sign-cmd').textContent = `dkms data sign -a demo-entity -m '${escaped}'`;
    log('Challenge loaded: nonce=' + chObj.nonce + ' purpose=' + chObj.purpose);
}

function assembleResponse() {
    const signed = $('signed-output').value.trim();
    if (!signed) return;

    const response = {
        entity_aid: window.entityState.aid,
        entity_oobi: typeof window.entityState.oobi === 'string'
            ? window.entityState.oobi
            : JSON.stringify(window.entityState.oobi),
        nonce: window.receivedChallenge.nonce,
        signed_challenge: signed,
    };
    const json = JSON.stringify(response, null, 2);
    $('response-output').textContent = json;
    show('response-output');
    show('response-transfer');

    window.clipboard.responseJson = json;
    log('Response assembled for nonce: ' + response.nonce);
}

function sendResponseToService() {
    const json = window.clipboard.responseJson;
    if (!json) return;

    const isLogin = window.receivedChallenge && window.receivedChallenge.purpose === 'identification';
    const targetTextarea = isLogin ? 'login-response-input' : 'entity-response-input';

    switchTab('service');
    $(targetTextarea).value = json;

    // Show formatted preview
    const previewId = isLogin ? 'login-response-preview' : 'entity-response-preview';
    let preview = $(previewId);
    if (!preview) {
        preview = document.createElement('div');
        preview.id = previewId;
        preview.className = 'payload';
        $(targetTextarea).parentElement.insertBefore(preview, $(targetTextarea));
    }
    preview.textContent = json;
    $(targetTextarea).style.display = 'none';

    log('Response sent to Service tab');

    const stepId = isLogin ? 'svc-step-8' : 'svc-step-6';
    show(stepId);
    $(stepId).scrollIntoView({ behavior: 'smooth' });
}
