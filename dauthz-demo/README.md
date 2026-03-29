# DAuthZ Web Demo

Interactive demo of DAuthZ registration and login ceremonies. Both Service and Entity sides are shown with step-by-step instructions for manual dkms CLI operations.

## Prerequisites

- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- Rust toolchain with `wasm32-unknown-unknown` target
- dkms binary + KERI infrastructure (witnesses on ports 3232/3233, watcher on 3235)

## Build

From the `dauthz-wasm/` directory:

```sh
wasm-pack build --target web --out-dir ../dauthz-demo/pkg
```

## Run

```sh
cd dauthz-demo
python3 -m http.server 8080
```

Open http://localhost:8080 in a browser.

## Usage

1. Start on the **Service** tab — create a service identifier using dkms, paste the AID and OOBI
2. Initialize the Service SDK (in-memory)
3. Issue a registration challenge
4. Switch to the **Entity** tab — create an entity identifier, paste AID and OOBI
5. Paste the challenge from the Service tab, resolve OOBI, sign it with dkms
6. Copy the assembled response back to the **Service** tab
7. Verify the response — registration complete
8. Continue with login challenges
