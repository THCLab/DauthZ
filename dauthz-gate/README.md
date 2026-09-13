# dauthz-gate

An `auth_request` sidecar that puts a Cyfron sign-in in front of anything
nginx serves, static files included. Users prove control of a KERI AID
with their Cyfron wallet; optionally they must also present a credential
(for example a Research Passport) issued by a configured authority.

```
browser ──► nginx ──auth_request──► dauthz-gate ──HTTP──► cyfron-serviced ──► witnesses
   │                                     ▲
   └── cyfron://auth deep link ──► Cyfron wallet ──POST /dauthz/connect/callback
```

No KERI cryptography runs in the gate. Every signature is verified by a
`cyfron-serviced` daemon that the gate talks to over HTTP with a bearer
token; the gate owns the ceremony, the policy and the session cookie.

## How a sign-in works

1. nginx asks `GET /dauthz/auth` for every request. Without a valid cookie
   the gate answers 401 and nginx redirects to `/dauthz/login?return=<uri>`.
2. The login page (the shared `dauthz-login-ui` bundle) calls
   `POST /dauthz/connect/init`, gets a `cyfron://auth?…` deep link and opens
   it (or shows it as a QR code for a phone, or lets the user copy it).
3. The wallet signs the `cyfron-sp-auth/1` envelope and POSTs it to
   `/dauthz/connect/callback`. The gate binds the signed nonce and AID to
   the challenge, resolves the user's OOBI, calls
   `POST /keri/verify-introduction` (which accepts the main AID, a
   confirmed delegated device, or a multisig member) and applies the policy.
4. The page polls `/dauthz/connect/status`, then hits
   `/dauthz/connect/finish?token=…` once. The gate sets an HMAC-signed,
   `HttpOnly` cookie and redirects to the original URI.

In credential mode the wallet may attach the credential to the callback
(`presented_credential`, needs a wallet that understands
`requested_credentials`), or the user is sent to `/dauthz/present` after
signing in and pastes the proof that Cyfron's Present dialog produces.
The presented ACDC must name the signed-in AID as its holder, carry the
configured schema (OCA bundle SAID) and issuer AID, and bear a valid
issuer signature. Only then does the cookie carry the credential SAID and
`/dauthz/auth` say yes.

## Run it

```sh
docker build -f dauthz-gate/Dockerfile -t dauthz-gate:local .   # from the DauthZ root
docker run --rm -p 8088:8088 -v gate-data:/data \
  -e DAUTHZ_SITE__ORIGIN=https://docs.example.org \
  -e DAUTHZ_CYFRON__URL=http://cyfron-serviced:51234 \
  -e DAUTHZ_CYFRON__TOKEN=… \
  -e DAUTHZ_POLICY__MODE=allowlist -e DAUTHZ_POLICY__ALLOWED_AIDS=EA…,EB… \
  dauthz-gate:local
```

Or with a file: `dauthz-gate --config gate.toml serve` (see
`config.example.toml`; env vars override the file). `dauthz-gate
check-config` prints the effective configuration, `print-identity` shows
the service AID/OOBI, `/dauthz/healthz` reports readiness and the callback
URL the wallets will use.

The first start creates the service identity on the daemon (`POST
/identifiers`) and persists it under `data_dir`; the cookie secret is
generated there too. Keep the volume.

### nginx

Include `nginx/dauthz-gate.locations.conf` inside the `server {}` block
and keep your normal `location /`:

```nginx
server {
    listen 80;
    root /usr/share/nginx/html;
    include /etc/nginx/dauthz/dauthz-gate.locations.conf;
    location / { try_files $uri /index.html; }
}
```

Any forward-auth proxy works the same way (Caddy `forward_auth
dauthz-gate:8088 { uri /dauthz/auth }`, Traefik `forwardAuth` with
`address: http://dauthz-gate:8088/dauthz/auth`), as long as `/dauthz/` is
proxied to the gate without auth.

### cyfron-serviced

The gate needs the daemon on a TCP listener with bearer auth:

```
cyfron-serviced --listen tcp://0.0.0.0:51234 --data-dir /data \
  --mesagkesto-url https://messagebox.dkms.colossi.network --service
CYFRON_SERVICED_ALLOW_REMOTE_BIND=1  CYFRON_AUTH_TOKEN=<shared token>
```

Do not publish the port; the gate reaches it on the docker network.
`cyfron.endpoint_file` can point at the daemon's `endpoint.json` instead of
a fixed token (the gate re-reads it on a 401).

## Policy

| `policy.mode` | Who gets in |
|---|---|
| `allowlist` | AIDs in `policy.allowed_aids` (re-checked on every request, so removal is immediate) |
| `credential` | any AID presenting a valid credential with `schema_said`, `issuer_aid`, `issuer_oobi` |
| `open` | any AID with a valid signature |

Credential mode knobs: `revocation_check` (`off`, `if_known` = deny only
when the registry says revoked, `required`), `presentation` (`inline`,
`page`, `both`), `requirement_text` for the login page.

### Research Passport runbook (credential mode)

1. The authority runs Cyfron desktop: create a governance, add an OCA
   repository, pull the passport OCA bundle by SAID, add each researcher as
   a contact, and use *Issue credential*. The credential is signed,
   anchored in the authority's TEL and delivered to the researcher, who
   accepts it in *Credentials*.
2. On the authority's daemon, print the gate policy lines:
   `dauthz-gate print-issuer-config --alias <authority alias> --schema-said <bundle SAID> --endpoint-file ~/.cyfron/endpoint.json`
3. Put those values in the gate's environment, set
   `DAUTHZ_POLICY__MODE=credential`, restart the gate.
4. A researcher signs in; the wallet either presents the passport in the
   callback or the user pastes the proof from *Credentials → Present* on
   the `/dauthz/present` page.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /dauthz/auth` | auth_request target: 204 + `X-DauthZ-AID`, or 401 |
| `GET /dauthz/login?return=` | sign-in page |
| `POST /dauthz/connect/init?return=` | mint a challenge and deep link |
| `POST /dauthz/connect/callback` | wallet callback (CORS `*`, nonce single-use) |
| `GET /dauthz/connect/status?nonce=` | `pending` / `approved` / `denied` / `expired` |
| `GET /dauthz/connect/finish?token=` | single-use handoff, sets the cookie |
| `GET|POST /dauthz/present` | paste a credential proof |
| `GET /dauthz/logout`, `GET /dauthz/whoami`, `GET /dauthz/healthz` | |

## Testing

```sh
cargo test -p dauthz-gate                      # unit + end-to-end with the mock bridge
cargo run -p dauthz-gate -- serve --mock-bridge  # demo without a daemon (no real signatures!)
MOCK=1 USER_AID=EA… SITE_URL=http://localhost:8088 scripts/smoke-callback.sh
CYFRON_URL=… CYFRON_TOKEN=… SITE_URL=http://localhost:8080 scripts/smoke-callback.sh   # real daemon
```

## Operational notes

- `site.origin` must be reachable by the *wallet*, not just the browser.
  Phones on the LAN need the host's IP, not `localhost`.
- Stale KELs: the daemon may hold a user's or the issuer's KEL from before
  their last rotation. The gate resolves OOBIs before verifying and
  re-resolves the issuer once on a credential failure; see cyfron's
  `docs/SP_AUTH_CONNECTIONS.md` for the repair endpoints.
- Ceremony state is in memory: a gate restart aborts sign-ins in flight
  only. Cookies are stateless and survive; they cannot be revoked before
  `cookie.ttl_secs` except through the allowlist.
- macOS/Windows wallets may lack the `cyfron://` handler; users can copy
  the URL into the app or scan the QR code with a phone.
