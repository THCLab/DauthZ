// ---------------------------------------------------------------------------
// "Connect with Cyfron" mode: dauthz-gate serves this page and the shared
// login page; dkms answers the cyfron://auth link in place of the Cyfron app.
// Everything here talks to the gate on the same origin (/dauthz/...).
// ---------------------------------------------------------------------------

const GATE = '/dauthz';
const RETURN_TO = '/?mode=connect';

function switchMode(mode) {
    document.querySelectorAll('.mode').forEach(b =>
        b.classList.toggle('active', b.dataset.mode === mode));
    $('mode-manual').classList.toggle('hidden', mode !== 'manual');
    $('mode-connect').classList.toggle('hidden', mode !== 'connect');
    const url = new URL(window.location.href);
    if (mode === 'connect') url.searchParams.set('mode', 'connect');
    else url.searchParams.delete('mode');
    history.replaceState(null, '', url);
    if (mode === 'connect') refreshConnect();
}

document.querySelectorAll('.mode').forEach(btn =>
    btn.addEventListener('click', () => switchMode(btn.dataset.mode)));

function renderRespondCommand() {
    const alias = $('conn-alias').value.trim() || 'demo-entity';
    $('conn-respond-cmd').textContent =
        `dkms auth respond -a ${alias} '<paste the cyfron://auth link here>'`;
}

async function checkGate() {
    const el = $('conn-gate-status');
    try {
        const resp = await fetch(GATE + '/healthz', { cache: 'no-store' });
        const h = await resp.json();
        if (h.ready) {
            el.textContent = `dauthz-gate is serving this page.\nService AID: ${h.service_aid}\n` +
                `Policy: ${h.policy_mode}\nCallback: ${h.callback_url}`;
            el.classList.remove('error');
            $('conn-signin').disabled = false;
        } else {
            el.textContent = 'dauthz-gate is starting: its service identifier is not ready yet ' +
                '(is demo-service created, and are the witnesses up?).';
            el.classList.add('error');
            $('conn-signin').disabled = true;
        }
        return h.ready;
    } catch {
        el.textContent = 'This page is not served by dauthz-gate. Start it with the command above ' +
            'and open http://localhost:8088/.';
        el.classList.add('error');
        $('conn-signin').disabled = true;
        return false;
    }
}

async function checkSession() {
    const el = $('conn-session');
    try {
        const resp = await fetch(GATE + '/whoami', { cache: 'no-store' });
        if (resp.status === 401) {
            el.textContent = 'Not signed in.';
            hide('conn-signout');
            return;
        }
        const who = await resp.json();
        const expires = new Date(who.exp * 1000).toLocaleString();
        el.textContent = `Signed in as ${who.aid}\n` +
            (who.signer_aid && who.signer_aid !== who.aid ? `Signed by ${who.signer_aid}\n` : '') +
            `Authorized: ${who.authorized}\nSession expires: ${expires}`;
        show('conn-signout');
        log('Connect session: ' + who.aid);
    } catch (e) {
        el.textContent = 'Session unknown: ' + e.message;
    }
}

async function refreshConnect() {
    if (await checkGate()) await checkSession();
}

$('conn-alias').addEventListener('input', renderRespondCommand);
$('conn-refresh').addEventListener('click', refreshConnect);
$('conn-signin').addEventListener('click', () => {
    log('Opening the login page');
    // The login page reads `return` raw, the way nginx passes $request_uri,
    // so the path goes in unencoded.
    window.location.href = GATE + '/login?return=' + RETURN_TO;
});
$('conn-signout').addEventListener('click', async () => {
    // The gate answers logout with a redirect to its login page; only the
    // cleared cookie matters here.
    await fetch(GATE + '/logout', { method: 'POST', redirect: 'manual' });
    log('Signed out');
    checkSession();
});

renderRespondCommand();
if (new URLSearchParams(window.location.search).get('mode') === 'connect') {
    switchMode('connect');
}
