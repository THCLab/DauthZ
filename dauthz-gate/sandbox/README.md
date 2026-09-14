# dauthz-gate sandbox

One `docker compose` rig that exercises the whole flow: nginx serving a
static directory, `dauthz-gate` as its `auth_request` backend, the gate's
own `cyfron-serviced`, and a second daemon that plays both the user's
wallet and the consortium authority. Identities use the public
`dkms.colossi.network` witness and watcher, so KEL resolution between the
two daemons is real.

```
make build             # release binaries on the host (bind-mounted into archlinux:base)
make up                # policy: open — any AID that can sign gets in
make smoke             # alice (on user-cyfron) signs the challenge headlessly -> 204 / cookie
make passport          # authority issues alice a passport; gate restarts in credential mode
make smoke-credential  # alice presents the passport in the callback -> 204
make smoke-bare        # alice signs in without it -> parked on /dauthz/present
```

`make status` prints the gate's health (service AID, callback URL) and the
current policy file. `make reset` wipes the daemons' data volumes.

## Browser test with a real wallet

Open the site URL printed by `make up`, click *Connect with Cyfron*.
`SITE_ORIGIN` defaults to your LAN IP so a phone or another machine's
wallet can POST the callback; override with `make SITE_ORIGIN=… up`.
After `make passport` the login page states the requirement; a wallet
that does not carry `requested_credentials` support lands on
`/dauthz/present`, where the proof from *Credentials → Present* can be
pasted. The sandbox passport is issued to the headless `alice` identity
on `user-cyfron`, not to your wallet, so for a browser credential test
issue one to your own AID from a Cyfron desktop governance instead
(see `../README.md`, runbook).

## What the pieces are

| Service | Role |
|---|---|
| `web` | `nginx:1.27-alpine` with `site/` and `../nginx/dauthz-gate.locations.conf` |
| `dauthz-gate` | `dauthz-gate serve`, env from the Makefile plus `.env.policy` |
| `sp-cyfron` | the gate's verifier daemon; token `sandbox-sp-token`; not published |
| `user-cyfron` | wallet + authority; published on `127.0.0.1:51235`, token `sandbox-user-token` |

`passport.sh` drives the authority through the same daemon endpoints the
desktop Governance view uses: create governance, add the OCA repository,
pull the schema by SAID (the default is the Colossi contact-card bundle,
standing in for a Research Passport schema), issue to alice with
`full_name`/`organization`/`job_title`, then write `.env.policy` with the
issuer's AID and OOBI. Delivery of the offer over messaging is best-effort
and may fail in the sandbox (alice is not the authority's contact); the
issued container is still valid and is saved to `state/passport.json`.

## Known limitation: revocation across daemons

`make revoke` flips the passport to `revoked` in the authority's TEL, but
`make smoke-revoked` still sees the SP daemon report the registry as
`unknown`, so under the default `revocation_check=if_known` policy the
revoked passport is still accepted (`required` would refuse it, along
with every other credential). The witness does serve the registry's
`vcp`, and cyfron-serviced now introduces the registry to the watcher and
polls `/query/tel`, but the public `watcher.dkms.colossi.network` never
answered with the TEL during testing. Until a watcher that forwards TELs
is available, revocation is only visible on the issuer's own daemon;
sessions are bounded by the cookie TTL and the credential's `exp`.

## Troubleshooting

- Gate stuck on `ready:false`: the first start creates the service
  identity through the witness; `make logs`. A witness outage shows as a
  retry loop.
- Callback `403 signature verification failed`: usually a KEL the SP
  daemon cannot fetch; check `make logs` for `resolve-oobi` errors and
  see cyfron's `docs/SP_AUTH_CONNECTIONS.md`.
- `GLIBC` errors at container start: the runtime image must match the
  host's glibc; rebuild with `docker compose build`.
