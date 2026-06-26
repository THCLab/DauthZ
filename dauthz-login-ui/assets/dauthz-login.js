// Shared DAuthZ login behaviour. Consumed verbatim by every plugin (Gerrit,
// Buildbot, …) via the dauthz-login-ui bundle. All per-plugin values arrive in
// a single JSON config object the backend injects as window.DAUTHZ_LOGIN — this
// file is fully static and contains no server-side template tokens.
//
// Config contract (see dauthz-login-ui/README.md):
//   {
//     "pluginBase":       "/plugins/dauthz",  // base for /connect/init|status|finish
//     "serviceName":      "Gerrit",
//     "registrationMode": "open" | "invite_only",
//     "requestedAttrs":   "name",
//     "serviceOobi":      "[{...}]",
//     "buildVersion":     "v1.2-abc1234"
//   }
(function() {
    const CFG = window.DAUTHZ_LOGIN || {};
    const PLUGIN_BASE = CFG.pluginBase || '';
    // Normalise the registration mode so the two backends (Gerrit emits
    // "invite_only", Buildbot "invite-only") drive the same UI branch.
    const REG_MODE = (CFG.registrationMode || 'open').replace('-', '_');
    const SERVICE_NAME = CFG.serviceName || 'this service';

    // ======== Populate per-plugin text from config ========
    function setText(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    document.title = 'Sign in — ' + SERVICE_NAME;
    setText('dz-h1-text', 'Sign in to ' + SERVICE_NAME);
    setText('dz-svc-strong', SERVICE_NAME);
    setText('dz-svc-name-oobi', SERVICE_NAME);
    setText('dz-attrs', CFG.requestedAttrs || 'name');
    setText('dz-svc-oobi', CFG.serviceOobi || '');
    setText('dz-build', CFG.buildVersion || '');

    const chip = document.getElementById('dz-mode-chip');
    if (chip) {
        chip.textContent = REG_MODE;
        chip.className = 'mode-chip ' + REG_MODE;
    }

    // ======== Connect with Cyfron (primary flow) ========

    let activePoll = null;
    let currentDeepLink = null;
    let currentStatusUrl = null;
    let currentFinishUrl = null;

    window.copyConnectUrl = async function() {
        const btn = document.getElementById('copy-url-btn');
        const statusEl = document.getElementById('connect-status');

        // If we already have a link from a prior connectWithCyfron call, just copy it.
        if (currentDeepLink) {
            doCopy(currentDeepLink, btn, 'Copy the URL', 'Copied!');
            return;
        }

        // Otherwise fetch a fresh session silently.
        btn.disabled = true;
        btn.textContent = 'Getting URL…';
        const invite = document.getElementById('invite-token').value.trim();
        let url = PLUGIN_BASE + '/connect/init';
        if (invite) url += '?invite=' + encodeURIComponent(invite);
        try {
            const resp = await fetch(url, { method: 'POST' });
            const data = await resp.json();
            if (!resp.ok) {
                btn.disabled = false;
                btn.textContent = 'Copy the URL';
                setStatus(statusEl, 'error', 'Could not start: ' + (data.error || resp.statusText));
                return;
            }
            currentDeepLink = data.deep_link;
            currentStatusUrl = data.status_url;
            currentFinishUrl = data.finish_url;
            doCopy(currentDeepLink, btn, 'Copy the URL', 'Copied!');
            // Start polling so the session isn't wasted.
            pollUntilSettled(currentStatusUrl, currentFinishUrl, statusEl, document.getElementById('connect-btn'));
        } catch (e) {
            btn.disabled = false;
            btn.textContent = 'Copy the URL';
            setStatus(statusEl, 'error', 'Request failed: ' + e.message);
        }
    };

    // ======== Sign in from your phone (QR code) ========
    // Renders the same connect deep link as a QR code so it can be scanned
    // by the Cyfron app on a phone. The flow is identical to the desktop
    // path: this tab keeps polling and signs in once the phone approves.
    let qrShown = false;

    window.showQrCode = async function() {
        const btn = document.getElementById('qr-btn');
        const statusEl = document.getElementById('connect-status');
        const wrap = document.getElementById('qr-wrap');
        const holder = document.getElementById('qr-code');

        // Toggle off if already showing.
        if (qrShown) {
            wrap.classList.add('hidden');
            holder.innerHTML = '';
            qrShown = false;
            btn.textContent = 'Sign in from your phone';
            return;
        }

        btn.disabled = true;
        btn.textContent = 'Preparing QR…';
        try {
            // Reuse an existing session if one was already started, otherwise
            // request a fresh one (carrying the invite token like the other flows).
            if (!currentDeepLink) {
                const invite = document.getElementById('invite-token').value.trim();
                let url = PLUGIN_BASE + '/connect/init';
                if (invite) url += '?invite=' + encodeURIComponent(invite);
                const resp = await fetch(url, { method: 'POST' });
                const data = await resp.json();
                if (!resp.ok) {
                    setStatus(statusEl, 'error', 'Could not start: ' + (data.error || resp.statusText));
                    btn.disabled = false;
                    btn.textContent = 'Sign in from your phone';
                    return;
                }
                currentDeepLink = data.deep_link;
                currentStatusUrl = data.status_url;
                currentFinishUrl = data.finish_url;
            }

            holder.innerHTML = '';
            new QRCode(holder, {
                text: currentDeepLink,
                width: 200,
                height: 200,
                colorDark: '#0e1422',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.M
            });
            wrap.classList.remove('hidden');
            qrShown = true;
            btn.disabled = false;
            btn.textContent = 'Hide QR code';

            // Same flow: poll so this tab signs in once the phone approves.
            pollUntilSettled(currentStatusUrl, currentFinishUrl, statusEl, document.getElementById('connect-btn'));
        } catch (e) {
            setStatus(statusEl, 'error', 'Could not show QR code: ' + e.message);
            btn.disabled = false;
            btn.textContent = 'Sign in from your phone';
        }
    };

    function doCopy(text, btn, idleLabel, doneLabel) {
        const done = () => {
            btn.disabled = false;
            btn.textContent = doneLabel;
            setTimeout(() => { btn.textContent = idleLabel; }, 1500);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done, () => { fallbackCopy(text); done(); });
        } else {
            fallbackCopy(text); done();
        }
    }

    function fallbackCopy(text) {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'absolute';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (e) { /* ignore */ }
        document.body.removeChild(ta);
    }

    const inviteRequiredHint = document.getElementById('invite-required-hint');
    if (inviteRequiredHint) {
        if (REG_MODE === 'invite_only') {
            inviteRequiredHint.textContent = 'required for new accounts';
        } else {
            inviteRequiredHint.textContent = 'optional';
        }
    }

    // Pre-fill invite token from ?invite=... query param.
    const urlParams = new URLSearchParams(window.location.search);
    const invitePrefill = urlParams.get('invite');
    if (invitePrefill) {
        document.getElementById('invite-token').value = invitePrefill;
    }

    window.connectWithCyfron = async function() {
        const btn = document.getElementById('connect-btn');
        const statusEl = document.getElementById('connect-status');
        btn.disabled = true;
        setStatus(statusEl, 'pending', 'Requesting connect session…');

        const invite = document.getElementById('invite-token').value.trim();
        let url = PLUGIN_BASE + '/connect/init';
        if (invite) url += '?invite=' + encodeURIComponent(invite);

        try {
            const resp = await fetch(url, { method: 'POST' });
            const data = await resp.json();
            if (!resp.ok) {
                setStatus(statusEl, 'error', 'Could not start: ' + (data.error || resp.statusText));
                btn.disabled = false;
                return;
            }

            // Store session so Copy the URL can reuse it without a second /connect/init.
            currentDeepLink = data.deep_link;
            currentStatusUrl = data.status_url;
            currentFinishUrl = data.finish_url;

            // Launch the Cyfron app via the deep link.
            setStatus(statusEl, 'pending', 'Opening Cyfron app…');
            window.location.href = data.deep_link;

            // Start polling for approval.
            pollUntilSettled(data.status_url, data.finish_url, statusEl, btn);
        } catch (e) {
            setStatus(statusEl, 'error', 'Request failed: ' + e.message);
            btn.disabled = false;
        }
    };

    function pollUntilSettled(statusUrl, finishBase, statusEl, btn) {
        if (activePoll) clearInterval(activePoll);
        setStatus(statusEl, 'pending', 'Waiting for approval in Cyfron…');

        let attempts = 0;
        const maxAttempts = 300; // ~5 minutes at 1s intervals
        activePoll = setInterval(async function() {
            attempts++;
            if (attempts > maxAttempts) {
                clearInterval(activePoll); activePoll = null;
                setStatus(statusEl, 'error', 'Timed out. Please try again.');
                btn.disabled = false;
                return;
            }
            try {
                const resp = await fetch(statusUrl);
                const data = await resp.json();
                if (data.state === 'approved' && data.handoff_token) {
                    clearInterval(activePoll); activePoll = null;
                    const label = data.new_account ? 'Account created. Signing you in…' : 'Signing you in…';
                    setStatus(statusEl, 'success', label);
                    window.location.href = finishBase + '?token=' + encodeURIComponent(data.handoff_token);
                    return;
                }
                if (data.state === 'denied') {
                    clearInterval(activePoll); activePoll = null;
                    // Gerrit returns `reason`, Buildbot returns `deny_reason`.
                    setStatus(statusEl, 'error', 'Declined: ' + (data.reason || data.deny_reason || 'user declined'));
                    btn.disabled = false;
                    return;
                }
                if (data.state === 'expired') {
                    clearInterval(activePoll); activePoll = null;
                    setStatus(statusEl, 'error', 'Session expired. Please try again.');
                    btn.disabled = false;
                    return;
                }
            } catch (e) {
                // Transient network error — keep polling.
            }
        }, 1000);
    }

    function setStatus(el, kind, msg) {
        el.textContent = msg;
        el.className = 'status ' + kind;
        el.classList.remove('hidden');
    }

    function setupCopy(el) {
        el.addEventListener('click', function() {
            navigator.clipboard.writeText(el.textContent.trim()).then(function() {
                el.classList.add('copied');
                setTimeout(function() { el.classList.remove('copied'); }, 1200);
            });
        });
    }

    document.querySelectorAll('.service-info .value').forEach(setupCopy);
})();
