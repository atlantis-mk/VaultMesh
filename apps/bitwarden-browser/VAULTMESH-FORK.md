# VaultMesh browser fork — independent development adapter

This is the experimental Bitwarden browser fork under `apps/bitwarden-browser`.
The downloaded source declared version `2026.9.0`; the archive does not establish
a verified Git commit. Upstream copyrights and GPL notices remain in place.
This directory is not a production replacement or a release declaration.

For realistic popup startup performance, use `npm run build:prod:chrome` (or
`npm run build:prod:firefox`) and reload `build/` in the extension manager.
These commands optimize JavaScript, but retain the independent development
extension identity and Native Host; they do not declare a product release.
Unminified `build:chrome` / watch builds remain available for debugging.

## Runtime boundary

The popup bootstraps a standalone Angular shell using the original Bitwarden tab
template, page/header, compact item/menu and generator presentation components.
Vault, generator and settings have separate routes; the VaultMesh controller owns
only remote state and privileged workflows. Routes stay in memory and never change
the independent editor's exact authorized document URL. Navigation clears drafts
and search; list pages render at most 25 summaries, with full-collection search.
The background starts only the original script generator and VaultMesh
RPC. Upstream account, SDK Vault, cloud sync, analytics, FIDO2 and notification
entrypoints are not bootstrapped or injected by this build.

The original heuristic generator was separated into
`src/autofill/services/autofill-script-generator.ts`; its matching, field roles,
custom field, TOTP splitting and native execution algorithms remain upstream.
It supports value-less remote planning without constructing cloud/account services.
No mock services or prototype-only objects are used in production.

Implemented adapter paths:

- Card, identity, SSH and ordinary Secret CRUD, full safe metadata editing and
  desktop-only protected clipboard operations. Card/identity/SSH expose existing
  trash/history; ordinary Secret deletion is explicitly permanent. Passkeys are excluded.
- PIN and biometric quick unlock/settings, desktop security settings, independent
  browser security preferences, pairing revocation, health and audit summaries.
- Password/passphrase/username/UUID generation with persisted parameters only;
  generated values expire after 60 seconds. Explicit copying uses the desktop's
  expiring clipboard; insertion binds the recently focused original field, native
  new-password/username roles, empty targets, authorization and document lifetime.
- Card/identity native value-less planning, qualified inline selection and explicit
  popup frame confirmation. Cards always re-prompt; the original generator formats
  expiry/select/country/state values only for the individually approved field.
- Card/identity Save/Ignore capture with explicit type selection for mixed forms,
  one-use frame/URL offers, and partial updates preserving unread card secrets and
  complete identity collections. Submission is not treated as server success.
- Explicit visible-page TOTP QR scan, direct content-to-popup response, candidate
  selection/overwrite confirmation and draft-only update. No QR UI is injected into pages.
- Global email OTP candidates in popup and native-qualified inline menus, 4–8
  character and segmented native planning/execution, one-use empty-field-only
  desktop assignments and a trusted-click 90-second watch. No email code audit/cache.
- Chromium native WebAuthn proxy create/get with independent authorization,
  conflict-safe attach/detach and Login-owned Passkey summary/deletion. Firefox has no proxy.
- Absent-Vault creation and confirmed master-password rotation through existing
  desktop operations. No browser-side Vault crypto, key wrapping or persistence.
- Independent unlock/status/lock, Login summaries/search and manual create/edit/delete.
- Desktop-owned Login username/password/TOTP clipboard operations; protected values
  do not return to the popup for copying.
- Login trash/history summaries, explicit restore/purge/clear with existing one-use
  desktop confirmation, stale-session cancellation and no uncertain-write retry.
- Recovery-code viewing and copying each require a newly entered master password.
  Viewed codes exist only in the active popup for at most 30 seconds; transport
  references are cleared after delivery and copy returns only clipboard expiry.
- The toolbar can open an independent editor window; drafts are not transferred.
  The background binds the exact created window/tab/URL, and navigation, reload or
  worker restart invalidates registration. In that window, recovery-code file
  dialogs may retain the current draft for at most 45 seconds without extending
  its original deadline. Ordinary focus loss, lock, close, cancel and expiry clear it.
  Import keeps the source file. Only an acknowledged save of the unchanged codes
  enables a separate native deletion confirmation; the desktop consumes a bounded
  one-use cleanup handle and rechecks the file digest. Cancellation keeps the file.
- Explicit Login fill across independently bound frames; cross-origin frames require
  selection of their actual URL in the popup.
- Native username/password/custom-field/TOTP planning. Custom planning reads only
  labels/indexes. TOTP seed and protected source values remain desktop-owned.
- Native-qualified input icon and same-form inline candidates; stale targets fail
  closed instead of broadening to the whole page. Reprompt retains the target.
- One-shot, empty-field-only automatic fill with stored preference, match ranking
  and a remembered opaque Login ID. Ambiguous equal-ranked matches do not auto-fill.
  Existing page usernames are compared locally; values never enter discovery.
- Observed submission offers Save/Ignore, not an assertion of server success.
  Protected capture values only leave content on Save. Update preserves untouched
  fields and unread secrets. Offers are one-use, bounded and navigation/auth-bound.
- After a successful explicit current-password fill in a reliable change form,
  Bitwarden password composition with Web Crypto entropy and the native executor
  fill the empty new/confirmation pair once. User-edited submitted values win.

All assignments remain origin/tab/frame/document/handle/expiry-bound and are
rechecked before each native write, including after pre-write page events.
Navigation, lock, disconnect, revocation, expiry and changed DOM ownership reject
stale work. No automatic submit or full-Cipher plaintext fallback exists.
Only completed credential writes are audited; audit failure never retries a fill.

Protected edit/capture values and generated passwords are transient. Existing
passwords, TOTP seeds and recovery codes are not fetched for Login editing; empty
replacement fields preserve them. Custom detail reads use fresh privileged
operations and are cleared after use. JavaScript cleanup is not guaranteed memory
zeroization. No Vault responses or authorization state enter extension storage;
the remembered-selection setting contains only an HTTP(S) origin and opaque ID.

## Independent development identity

The user selected coexistence, not replacement of the existing WXT extension.
`development-identity.json` owns the public development key and identifiers:

- Chromium ID: `edggbpbfcfagdnhiameocjapmggojhka`
- Firefox ID: `bitwarden-dev@vaultmesh.local`
- Native Host: `com.vaultmesh.bitwarden.dev`

The public key is not a signing credential or authorization secret.
Host registration/config, IPC endpoint, pairing/PIN/biometric credentials and
Broker runtime authorization are isolated from the existing extension.
The secondary desktop listener only runs in a debug build with explicit
`VAULTMESH_BITWARDEN_DEVELOPMENT=1`. A release build of the dev Host refuses use.
The original extension ID, Host allowlist and pairing records must not be changed.

Preparation commands, from this directory (not executed as installation tests):

```sh
npm run native:host:build
npm run native:host:plan
# Explicitly installs only the dedicated development Host registration:
npm run native:host:install
```

Run the existing Tauri debug command from the repository root with
`VAULTMESH_BITWARDEN_DEVELOPMENT=1` in its environment. Do not use the existing
`browser:dev` pairing-reset orchestration for this fork.
Real Host installation, browser loading and website testing remain deferred
at the user's request. No real Vault or credentials were used for fixtures.

## Isolated dependencies and verification

Shared libraries, npm dependencies, aliases, compiler/loader/style paths and caches
are local to this directory. Builds do not depend on Downloads or parent Node
packages. `upstream-dependencies.json` records dependency/config provenance.
The one-time importer refuses to overwrite existing libraries; upstream updates
require a reviewed merge.

```sh
npm ci
npm run typecheck
npm run test:adapter
npm run identity:test
npm run dependencies:test
node --test scripts/vaultmesh-contract-parity.test.mjs
npm run build:chrome
npm run build:firefox
```

Both browser builds replace local `build/`, so run them sequentially.
`test:adapter` runs the active adapter and original autofill-engine regression suites;
it does not claim the unbootstrapped upstream account/cloud UI is integrated.
`src/vaultmesh/vendor` contains exact projections of desktop-owned contracts
and policy; parity tests prevent a second schema owner.

## Remaining migration and acceptance

SSH/Secret fill and capture are connected alongside card/identity and generator
insertion/copy. SSH public-key/title uses the original upstream branch; VaultMesh-only
credential roles use its exact custom-field matcher and closed typed source plans.
Only explicit HTTPS empty-field assignments are allowed; no generic key/password
fallback, automatic credential disclosure or ordinary Secret access to Passkeys.
This does not establish complete website parity: real-site and platform acceptance
remain deferred by the user.
Vault backup/restore, bulk file import and SSH scan/import are desktop-only for this
migration, per the user's scope decision; they are not remaining extension work.
Do not add popup/RPC entrypoints or new native-dialog lifecycle exceptions for them.
Existing desktop/original-extension compatibility contracts and the separately
approved recovery-code editor helper are retained.
Native plans authorize Login plus closed card/identity/SSH/Secret sources;
new sources require the desktop-owned contract, never a WXT matching fallback.
The approved hidden-editor draft exception covers only recovery-code file dialogs;
the desktop-only workflows do not require extending that exception.
The new file dialog/editor-window flow still needs target-browser/native-dialog acceptance.
Unsupported upstream
commands/routes must not be exposed as working integrations.

Code tests and successful builds do not establish real-site compatibility,
native installation, Windows acceptance, signed packaging or distribution
license clearance. Do not publish this development build as a complete client.

The 2026-09-12 production dependency audit flags seven affected Angular dependency
entries (three high and four moderate) at the current 21.2.17 pin; runtime reachability
and remediation still require review. No force-upgrade was applied. Local checks
currently run on Node 24.12.0, below the upstream declared minimum of 24.17.0.

## Branding

VaultMesh product names, toolbar/inline icons and core localized branding use
assets from `apps/browser-extension/public`. Upstream copyrights, licenses,
compatibility attributes and genuine third-party product names remain intact.
Use `npm run branding:sync` and `npm run branding:test` for the isolated branding
workflow. Safari/store artwork is outside the current Chromium/Firefox work.
