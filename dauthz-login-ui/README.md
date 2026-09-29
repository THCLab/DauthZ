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
  dauthz-login.js     all behaviour; reads the JSON config data block
  qrcode.min.js       vendored QR renderer (rendered client-side; the deep link
                      never leaves the device)
VERSION               bump on any asset change; drift checks compare against it.
                      Also update UI_VERSION in dauthz-login.js (shown in the
                      page footer); dauthz-gate's tests fail if they differ.
```

## How a backend serves it

1. Serve `dauthz-login.css`, `dauthz-login.js`, `qrcode.min.js` as static files
   under some base path (e.g. `…/ui`).
2. Serve `dauthz-login.html` with three textual substitutions:
   - `{{ASSET_BASE}}` → the URL base where the three static files are served.
   - `{{THEME_HEAD}}` → extra `<link>`/`<style>` for a theme override, or `""`.
   - `/*__DAUTHZ_CONFIG__*/{}` → a single JSON object (the config below). It
     sits inside `<script id="dauthz-login-config" type="application/json">`,
     a JSON data block rather than executable JavaScript; substitute the token
     with bare JSON, not with an assignment statement.

No other templating is required; the JS fills every per-plugin text node from
config at load.

## Config contract (`#dauthz-login-config`)

```jsonc
{
  "pluginBase":       "/plugins/dauthz", // base for /connect/init|status|finish
  "serviceName":      "Gerrit",          // shown in title, heading, lede, OOBI label
  "registrationMode": "open",            // "open" | "invite_only" (or "invite-only")
  "requestedAttrs":   "name",            // human string, e.g. "name, email"
  "serviceOobi":      "[{...}]",         // service OOBI trust anchor; never shown,
                                         // only copied via the "Copy OOBI" button
  "buildVersion":     "v1.2-abc1234",    // backend provenance, appended to the
                                         // "DAuthZ login <ui version>" footer
  // Optional, added in 1.2.0:
  "returnTo":          "/guides/x",      // sent as ?return= on /connect/init
  "hideInvite":        true,             // hide the invite field (no invites)
  "accessRequirement": "Requires a …"    // extra sentence under the lede
}
```

`returnTo` is the path to land on after sign-in; a backend that gates a whole
site passes the originally requested path here (the JS also picks up
`?return=` from the login page URL). Every `/connect/init` call — button,
copy-URL and QR — carries it together with the invite token.

`registrationMode` accepts either `invite_only` or `invite-only`; the JS
normalises the hyphen so Gerrit and Buildbot can pass their native spelling.

Bundles before 1.1.0 delivered this object as an inline
`<script>window.DAUTHZ_LOGIN = …</script>`. The JS still falls back to
`window.DAUTHZ_LOGIN` if it is defined, so a backend can migrate its
substitution at its own pace, but the inline form requires
`script-src 'unsafe-inline'` and should be retired.

## Content-Security-Policy

The bundle is CSP-clean: no inline `<script>`, no inline event handlers
(`onclick=`), no `eval`. Hosts with a strict policy — OpenProject, for one —
can serve it without weakening `script-src`. What it does need:

```
script-src  'self';                                   # the two bundled .js files
style-src   'self' https://fonts.googleapis.com;      # webfont stylesheet
font-src    https://fonts.gstatic.com;                # webfont files
img-src     'self' data:;                             # QR code renders to a data: URI
connect-src 'self';                                   # /connect/init and status polling
```

The two font entries are only needed if the host allows the Google Fonts
`<link>`; drop it (or override it via `{{THEME_HEAD}}`) and the page falls back
to the system font stack with no other change. `img-src data:` is required
because the vendored QR renderer draws to a canvas and emits a `data:` image.
Adjust the origins if the assets are served from a separate host.

## Backend flow contract

The JS calls, relative to `pluginBase`:
- `POST {pluginBase}/connect/init[?invite=…][&return=…]` →
  `{ nonce, deep_link, status_url, finish_url, expires_at }`
- polls `status_url` → `{ state: "pending"|"approved"|"denied"|"expired", … }`
  - approved → `{ handoff_token, new_account? }`
  - denied → `{ reason }` **or** `{ deny_reason }` (both accepted)
- on approval redirects to `finish_url?token=<handoff_token>`; `finish_url`
  must not carry a query string

## Theming

Override by redefining the `:root` Cyfron design tokens (or any selector) in a
stylesheet supplied via `{{THEME_HEAD}}`. Behaviour is identical across plugins;
only presentation is overridable.

## Consumers

- `dauthz-gate` embeds the files at compile time (`include_str!`).
- The Gerrit plugin vendors them with `scripts/sync-login-ui.sh`; run it
  with `DAUTHZ_LOGIN_UI_DIR=<this directory>` after every change here and
  commit the result.

## Changing the UI

Edit assets here, bump `VERSION`, then re-run each plugin's
`scripts/sync-login-ui.sh` and commit the synced copies. CI drift checks fail if
a plugin's vendored copy diverges from this source.
