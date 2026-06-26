# dauthz-login-ui

Canonical, language-agnostic login UI shared by every DAuthZ service plugin
(Gerrit, Buildbot, …). It is the **single source of truth** for the
"Connect with Cyfron" sign-in page: markup, styling, QR code, polling, copy-URL
and invite handling all live here once.

Each plugin's backend keeps its own job — serving bytes and minting sessions —
but no longer carries its own copy of the page. The bundle is vendored into each
plugin at build time (committed, like a vendored library) and kept in sync by a
drift check; see `scripts/sync-login-ui.sh` in each plugin repo.

## Assets

```
assets/
  dauthz-login.html   skeleton (per-plugin values injected, not hard-coded)
  dauthz-login.css    base styles + Cyfron design tokens (:root variables)
  dauthz-login.js     all behaviour; reads window.DAUTHZ_LOGIN
  qrcode.min.js       vendored QR renderer (rendered client-side; the deep link
                      never leaves the device)
VERSION               bump on any asset change; drift checks compare against it
```

## How a backend serves it

1. Serve `dauthz-login.css`, `dauthz-login.js`, `qrcode.min.js` as static files
   under some base path (e.g. `…/ui`).
2. Serve `dauthz-login.html` with three textual substitutions:
   - `{{ASSET_BASE}}` → the URL base where the three static files are served.
   - `{{THEME_HEAD}}` → extra `<link>`/`<style>` for a theme override, or `""`.
   - `/*__DAUTHZ_CONFIG__*/{}` → a single JSON object (the config below).

No other templating is required; the JS fills every per-plugin text node from
config at load.

## Config contract (`window.DAUTHZ_LOGIN`)

```jsonc
{
  "pluginBase":       "/plugins/dauthz", // base for /connect/init|status|finish
  "serviceName":      "Gerrit",          // shown in title, heading, lede, OOBI label
  "registrationMode": "open",            // "open" | "invite_only" (or "invite-only")
  "requestedAttrs":   "name",            // human string, e.g. "name, email"
  "serviceOobi":      "[{...}]",         // service OOBI trust anchor
  "buildVersion":     "v1.2-abc1234"     // provenance string, bottom-right
}
```

`registrationMode` accepts either `invite_only` or `invite-only`; the JS
normalises the hyphen so Gerrit and Buildbot can pass their native spelling.

## Backend flow contract (unchanged, already shared)

The JS calls, relative to `pluginBase`:
- `POST {pluginBase}/connect/init` → `{ deep_link, status_url, finish_url }`
- polls `status_url` → `{ state: "pending"|"approved"|"denied"|"expired", … }`
  - approved → `{ handoff_token, new_account? }`
  - denied → `{ reason }` **or** `{ deny_reason }` (both accepted)
- on approval redirects to `finish_url?token=<handoff_token>`

## Theming

Override by redefining the `:root` Cyfron design tokens (or any selector) in a
stylesheet supplied via `{{THEME_HEAD}}`. Behaviour is identical across plugins;
only presentation is overridable.

## Changing the UI

Edit assets here, bump `VERSION`, then re-run each plugin's
`scripts/sync-login-ui.sh` and commit the synced copies. CI drift checks fail if
a plugin's vendored copy diverges from this source.
