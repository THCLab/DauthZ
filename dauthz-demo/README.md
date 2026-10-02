# DAuthZ Web Demo

Interactive demo of DAuthZ sign-in in two modes:

- **Manual ceremony** — registration and login with both the Service and
  Entity sides on one page, every dkms CLI step done by hand (copy, run,
  paste back). Shows what the protocol does underneath.
- **Connect with Cyfron** — the production flow (optionally requiring a
  *passport* credential, see below): the service hands out a
  `cyfron://auth` link through the shared login page
  (`dauthz-login-ui`), a wallet signs it and the browser completes the
  sign-in on its own. Here `dauthz-gate` is the service, verifying with the
  dkms CLI instead of cyfron-serviced, and `dkms auth respond` is the
  wallet, so no Cyfron software is involved.

## Prerequisites

- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- Rust toolchain with `wasm32-unknown-unknown` target
- dkms (dkms-bin) in PATH, with `dkms auth` for the Connect mode
- KERI infrastructure (witnesses on ports 3232/3233, watcher on 3235)

On a host with the kernel's DKMS tool installed, `dkms` in PATH may be
`/usr/bin/dkms`; put dkms-bin first or set `DKMS_BINARY` for the gate.

## Build

From the `dauthz-wasm/` directory:

```sh
wasm-pack build --target web --out-dir ../dauthz-demo/pkg
```

## Run

Either serve the directory on its own (manual mode only):

```sh
cd dauthz-demo
python3 -m http.server 8080
```

or let dauthz-gate serve it, which both modes need. From the repository
root:

```sh
dkms identifier init -a demo-service --witness-url http://172.17.0.1:3232 \
    --witness-url http://172.17.0.1:3233 --watcher-url http://172.17.0.1:3235
cargo run -p dauthz-gate -- --config dauthz-demo/gate.demo.toml serve
```

and open http://localhost:8088/. `gate.demo.toml` runs the gate with the
dkms bridge, an open policy and the demo directory as its static site.

## Usage: manual ceremony

1. Start on the **Service** tab — create a service identifier using dkms, paste the AID and OOBI
2. Initialize the Service SDK (in-memory)
3. Issue a registration challenge
4. Switch to the **Entity** tab — create an entity identifier, paste AID and OOBI
5. Paste the challenge from the Service tab, resolve OOBI, sign it with dkms
6. Copy the assembled response back to the **Service** tab
7. Verify the response — registration complete
8. Continue with login challenges

## Usage: Connect with Cyfron

1. Switch to **Connect with Cyfron**; the page checks that the gate is up
   and shows the service AID.
2. Create the wallet-side identifier: `dkms identifier init -a demo-entity …`
3. Press **Sign in with Cyfron**. On the login page press **Copy URL** and
   answer the link:

   ```sh
   dkms auth respond -a demo-entity 'cyfron://auth?nonce=…'
   ```

   dkms shows which service is asking and asks before it signs. The login
   page sees the answer within a second and returns to the demo, now
   signed in; **Sign out** clears the session.

The login page's **Connect with Cyfron** button opens the `cyfron://` link
directly once a handler is registered; the dkms-bin README has a
`.desktop` handler that runs `dkms auth respond`.

## Usage: requiring a passport

The gate can also require a credential on top of the AID sign-in. The demo
calls it a *passport*: a credential with `full_name` and `nationality`,
issued by a `demo-authority` identifier to your `demo-entity`, under the
schema in `passport.schema.json` (identified by that file's SAID).

1. Issue a passport (the authority is created on the first run):

   ```sh
   dauthz-demo/passport.sh "Ada Lovelace" GB
   ```

   It writes `target/dauthz-demo/passport.json` (the proof you present:
   `{said, acdc, issuer_cesr}`) and `target/dauthz-demo/passport.env` (the
   gate policy: credential mode, this schema, this authority).
2. Restart the gate with that policy:

   ```sh
   (set -a; . target/dauthz-demo/passport.env; set +a; \
    cargo run -p dauthz-gate -- --config dauthz-demo/gate.demo.toml serve)
   ```

   The demo page now marks the passport as required and the login page
   states the requirement.
3. Sign in presenting it:

   ```sh
   dkms auth respond -a demo-entity --present target/dauthz-demo/passport.json '<cyfron://auth link>'
   ```

   Or sign in without `--present`: the gate lets you in as far as its
   passport page, where you paste the contents of `passport.json`.

The gate checks that the passport was issued to the signed-in AID, by the
configured authority, under the passport schema, and that the authority's
signature covers it. It does not check revocation: with the dkms bridge
the registry status stays unknown, which the demo's `if_known` policy
admits. Querying the authority's registry through a watcher returned stale
state in testing and takes about half a minute per check.

Restart the gate without the env file to go back to the open policy.
