# Next Steps

## Prioritized Roadmap

### P0: Release-Critical Identity Safety

- Finish live verification for username collision after create-time retry handling.
- Capture actual OIDC claims for an intended unverified-email account and confirm `email_verified === false` is rejected.
- Investigate post-callback hangs after successful login.
- Confirm stale `authentik:sub:uid` cleanup in live data.
- Keep the first release focused on reliable login, no duplicate accounts by verified email, safe collision handling, and clear operational documentation.

### P1: Operator Safety And Diagnostics

- Expand ACP diagnostics enough to debug live failures without exposing secrets or raw tokens.
- Add mapping audit and stale mapping repair.
- Add configurable authorization parameters for Authentik account selection or fresh login.
- Add admin-selectable username collision behavior.
- Keep repair and diagnostics conservative: explicit confirmation for destructive actions, short retention, and sanitized output only.

### P2: NodeBB User Profile Controls

- Add user-facing profile controls for viewing OIDC link state and controlling NodeBB-owned preferences.
- Expose Authentik-managed profile actions through redirects or clearly marked external links where practical.
- Do not let users edit identity-critical OIDC state from NodeBB. `sub`, issuer, and verified-email link mappings remain admin/plugin controlled.

### P3: Profile Synchronization

- Add explicit per-field Authentik-to-NodeBB synchronization after identity resolution.
- Keep sync disabled by default or limited to low-risk fields until diagnostics and conflict policies are solid.
- Treat email sync and username sync as higher-risk than display name/avatar sync because they affect account recovery, mentions, and user recognition.

### P4: Authentik-Side Enrollment Polish

- Document Authentik flow/policy recipes for duplicate username/email rejection, required email, claim mapping, account selection, and external profile management.
- Add optional deep links from NodeBB to Authentik self-service flows, but do not make the NodeBB plugin depend on Authentik admin APIs for core login.

## Release Blockers

- Verify the username-collision behavior after the latest retry handling. Decide whether the release policy is to create a unique NodeBB username or to reject collisions entirely.
- Capture actual OIDC claims for an Authentik account intended to be unverified. The live test is not complete until the emitted `email_verified` claim is confirmed to be boolean `false`.
- Investigate the post-callback hang seen after repeat login. Confirm whether NodeBB is waiting on a response, redirecting to an interstitial, or completing login with a frontend routing issue.
- Confirm stale `authentik:sub:uid` cleanup in live data by deleting a mapped test user and retrying with the same Authentik subject.

## Plugin Hardening

- Add sanitized claim diagnostics for failed callbacks. Include rejection code, claim presence, `email_verified` type/value, issuer, and whether userinfo was used. Never store or log raw tokens.
- Add optional admin-configurable authorization parameters for Authentik flows, especially `prompt=login` or `prompt=select_account`, to reduce accidental reuse of an existing Authentik browser session.
- Add an admin setting for username-collision policy:
  - `unique`: create a safe unique NodeBB username for new SSO users.
  - `reject`: fail new SSO account creation if `preferred_username` conflicts with an existing NodeBB username/userslug.
- Add a small admin/CLI repair tool to list and remove stale `authentik:sub:uid` mappings whose uid no longer exists.
- Add tests around NodeBB's userslug collision behavior, not only exact username matching.

## Avatar Investigation

- Reproduce the "new Authentik user receives existing NodeBB avatar" issue with a clean incognito session and browser devtools network log.
- Capture the resolved NodeBB uid, Authentik `sub`, `picture` claim, NodeBB `picture` field, and any OAuth/avatar-related request URLs immediately after account creation.
- Verify whether the avatar shown is coming from NodeBB user data, a cached browser image, Authentik's account-selection UI, or theme-level rendering.
- Ensure new SSO-created users do not inherit `picture`, `uploadedpicture`, `icon:text`, `icon:bgColor`, or any profile fields from the currently logged-in NodeBB session.
- Add a test fixture for user creation where another NodeBB session/user exists, and assert only the resolved uid is updated.
- If Authentik provides a `picture` claim, apply it only through explicit avatar synchronization settings; otherwise leave NodeBB's default generated avatar behavior intact.

## Account Synchronization

- Add admin settings for Authentik-as-source-of-truth synchronization:
  - Email sync: update NodeBB email only when provider `email_verified === true`.
  - Username sync: update NodeBB username from `preferred_username` only if enabled and conflict policy passes.
  - Display name sync: update fullname from `name`.
  - Avatar sync: update NodeBB avatar from OIDC `picture` only if enabled and URL passes validation.
  - Custom field sync: map explicit OIDC claim names to NodeBB user fields.
- Store sync audit fields on each user: `authentikLastSyncedAt`, `authentikLastEmail`, `authentikLastUsername`, and per-field sync status when practical.
- Make synchronization happen after identity resolution by `sub`, never before identity resolution.
- Treat synchronization failures as field-level warnings by default, not login failures, except for email conflicts or identity-critical fields.
- Add dry-run diagnostics in ACP showing what would change for a selected uid/sub without applying writes.
- Add tests for changed email, username conflict, avatar URL validation, missing claims, custom field mapping, and local user edits being overwritten only when sync is enabled.

## ACP Configuration And UX

- Rework the ACP page into clear sections:
  - Provider connection: enabled, display name, issuer, discovery, endpoints, JWKS URI, client id, client secret, scopes, callback URL.
  - Login behavior: authorization parameters, PKCE toggle, HTTPS development override, local login policy, registration/account creation policy.
  - Identity rules: verified-email requirement, username collision policy, email collision behavior, stale mapping cleanup behavior.
  - Synchronization: per-field sync toggles for email, username, fullname, avatar, and custom claim mappings.
  - Diagnostics and repair: test discovery, test provider connection, inspect sanitized last failure, audit mappings, repair stale mappings.
- Add switches and levers:
  - Enable/disable plugin.
  - Use PKCE.
  - Allow insecure callback URL for local development only.
  - Force account selection/fresh Authentik login via preset authorization parameters.
  - Allow new SSO account creation versus link existing accounts only.
  - Username collision policy: generate unique, keep existing/local, or reject.
  - Sync toggles: email, username, display name, avatar, custom fields.
  - Avatar behavior: disabled, use provider `picture`, preserve local, or reset to NodeBB default.
  - Diagnostics mode with short retention.
- Add validation and operator feedback:
  - Inline validation for missing required fields, invalid URLs, non-HTTPS URLs, missing `openid` scope, invalid custom claim mappings, and dangerous authorization parameters.
  - Clear "saved secret is present" status without exposing the secret.
  - Discovery result preview showing issuer, endpoints, supported scopes, and token auth methods.
  - Callback URL copy button and visible warning when NodeBB's configured base URL does not match the expected public URL.
  - Save button disabled while requests are in flight, with success/failure alerts that include field-level errors.
- Add diagnostics tools:
  - "Test discovery" fetches `.well-known/openid-configuration` and validates issuer.
  - "Test JWKS" verifies the JWKS endpoint is reachable and has supported signing keys.
  - "Show sanitized last failure" displays rejection code and claim presence/type metadata without tokens.
  - "Audit mappings" lists stale `sub` mappings, users with `authentikSub` but missing reverse mapping, and duplicate mappings.
  - "Dry-run sync" shows what fields would change for a selected uid or `sub`.
- Add safety guardrails:
  - Require confirmation before enabling account creation, destructive repair actions, or sync modes that overwrite local profile fields.
  - Do not display raw client secret, tokens, authorization codes, ID tokens, or full claim payloads in ACP.
  - Mark development-only settings clearly and keep them disabled by default.
- Add ACP tests or fixtures for save/reload, placeholder secret preservation, discovery preview, validation errors, toggles, and diagnostics endpoints.

## User Profile OIDC Controls

- Add a NodeBB user settings/profile panel for linked accounts that initially shows only NodeBB-controlled information:
  - Linked status.
  - Provider display name.
  - Linked issuer.
  - Last login time.
  - Last sync time.
  - Last provider email seen.
  - Whether the current NodeBB email is provider-verified.
  - Which local fields are managed by Authentik sync.
- Add user-facing NodeBB controls where safe:
  - Re-run Authentik login to refresh/sync profile data.
  - Disconnect Authentik only if local login/password or another safe login method exists, and only if admin policy allows disconnect.
  - Choose local notification/digest settings. These remain NodeBB-owned unless future mapping says otherwise.
  - Preserve or reset local avatar when avatar sync is disabled.
- Add external Authentik actions where practical:
  - Link to Authentik self-service profile page.
  - Link to Authentik password/account settings if configured.
  - Link to Authentik MFA/device settings if configured.
  - Link to Authentik consent/session management if configured.
- Add ACP-configurable URLs for those external actions rather than hardcoding Authentik paths.
- Add clear read-only labels for Authentik-managed fields. If username, email, display name, or avatar sync is enabled, the NodeBB profile UI should explain that changes must be made in Authentik.
- Add guardrails:
  - Users cannot edit or delete `authentikSub`, issuer, or reverse mapping.
  - Users cannot force-link a different Authentik account over an existing `sub`.
  - Disconnect requires admin policy, CSRF protection, confirmation, and a fallback login method.
  - Refresh/sync actions must resolve identity by the current linked `sub`, not by username or user-supplied email.
- Add tests for profile panel visibility, permissions, disconnect policy, refresh sync, external link rendering, and read-only managed field indicators.

## Authentik Hardening

- Configure Authentik enrollment flows to require email before account creation completes.
- Configure Authentik policies to reject duplicate usernames and duplicate emails before redirecting back to NodeBB.
- Confirm the Authentik provider maps the real email verification state into the OIDC `email_verified` claim.
- Consider forcing account selection or fresh login for the NodeBB provider flow if browser sessions make the wrong Authentik account visually appear during registration.
- Configure Authentik to emit only intended profile claims for NodeBB, including `preferred_username`, `name`, `email`, `email_verified`, and optionally `picture`.
- Decide whether Authentik should prevent profile changes locally in NodeBB by policy, UI messaging, or future plugin settings.

## Live Cleanup

- Remove accidental duplicate NodeBB users created during testing.
- Remove or repair stale `authentik:sub:uid` mappings for deleted test users.
- Audit users with `authentikSub` and confirm each has exactly one matching entry in `authentik:sub:uid`.
- Audit test Authentik users with missing email or duplicate emails and remove them once provider-side policies are in place.
