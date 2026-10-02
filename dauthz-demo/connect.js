// ---------------------------------------------------------------------------
// "Connect with Cyfron" mode: dauthz-gate serves this page and the shared
// login page; dkms answers the cyfron://auth link in place of the Cyfron app.
// Everything here talks to the gate on the same origin (/dauthz/...).
// ---------------------------------------------------------------------------

const GATE = '/dauthz';
const RETURN_TO = '/?mode=connect';
const PASSPORT_FILE = 'target/dauthz-demo/passport.json';

// Set from /healthz: does the running gate require a passport?
let passportRequired = false;

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
    const present = passportRequired ? ` --present ${PASSPORT_FILE}` : '';
    $('conn-respond-cmd').textContent =
        `dkms auth respond -a ${alias}${present} '<paste the cyfron://auth link here>'`;
    $('conn-respond-hint').textContent = passportRequired
        ? '--present sends the passport with the sign-in. Without it the gate signs you in, ' +
          `then asks you to paste ${PASSPORT_FILE} on its passport page.`
        : 'dkms shows which service is asking and asks before it signs. The login page ' +
          'notices the answer within a second and brings you back here.';
}

function renderPassportStep() {
    const badge = $('conn-passport-badge');
    badge.textContent = passportRequired ? 'required' : 'optional';
    badge.classList.toggle('required', passportRequired);
    $('conn-passport-intro').textContent = passportRequired
        ? 'This gate requires a passport: a credential issued by the demo authority to your ' +
          'identifier. Signing in proves who you are; the passport proves you may enter.'
        : 'The gate can also require a credential: a passport issued by a demo authority to ' +
          'your identifier. Signing in then proves both who you are and that you hold a passport.';
    $('conn-passport-hint').textContent = passportRequired
        ? 'Running with the passport policy. Restart without the env file to go back to the open policy.'
        : 'Running with the open policy: any identifier with a valid signature may sign in.';
}

async function checkGate() {
    const el = $('conn-gate-status');
    try {
        const resp = await fetch(GATE + '/healthz', { cache: 'no-store' });
        const h = await resp.json();
        passportRequired = h.policy_mode === 'credential';
        renderPassportStep();
        renderRespondCommand();
        if (h.ready) {
            el.textContent = `dauthz-gate is serving this page.\nService AID: ${h.service_aid}\n` +
                `Policy: ${passportRequired ? 'passport required' : h.policy_mode}\n` +
                `Callback: ${h.callback_url}`;
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
            el.classList.remove('error');
            hide('conn-signout');
            hide('conn-present');
            return;
        }
        const who = await resp.json();
        const expires = new Date(who.exp * 1000).toLocaleString();
        let passport = '';
        if (who.cred_said) passport = `Passport: ${who.cred_said}\n`;
        else if (passportRequired) passport = 'Passport: not presented yet, so access is refused\n';
        el.textContent = `Signed in as ${who.aid}\n` +
            (who.signer_aid && who.signer_aid !== who.aid ? `Signed by ${who.signer_aid}\n` : '') +
            passport +
            `Authorized: ${who.authorized}\nSession expires: ${expires}`;
        el.classList.toggle('error', !who.authorized);
        show('conn-signout');
        $('conn-present').classList.toggle('hidden', who.authorized || !passportRequired);
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
$('conn-present').addEventListener('click', () => {
    window.location.href = GATE + '/present?return=' + encodeURIComponent(RETURN_TO);
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
