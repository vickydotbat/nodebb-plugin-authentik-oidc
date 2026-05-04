# Next Steps

## Prioritized Roadmap

### P0: Release-Critical Identity Safety

- Run one final live Authentik pass after rebuilding NodeBB with the current plugin code.
- Capture actual OIDC claims for an intended unverified-email account and confirm `email_verified === false` is rejected. Use ACP Last failure diagnostics after the rejected callback; inspect provider-side token/userinfo only as needed.
- Retest post-callback completion after successful repeat login and confirm the browser receives the NodeBB success redirect cleanly.
- Confirm stale `authentik:sub:uid` cleanup in live data through the ACP mapping audit and repair flow.
- Keep the first release focused on reliable login, no duplicate accounts by verified email, safe collision handling, and clear operational documentation.

### P1: Operator Safety And Diagnostics

- Expand ACP diagnostics enough to debug live failures without exposing secrets or raw tokens.
- Add mapping audit and stale mapping repair.
- Add configurable authorization parameters for Authentik account selection or fresh login.
- Add admin-selectable username collision behavior.
- Add NodeBB session revocation support for upstream Authentik logout/session closure.
- Added sanitized ACP diagnostics for the last back-channel logout request so operators can tell whether Authentik called NodeBB, whether the logout token validated, and whether `sub`/`sid` matched a NodeBB mapping.
- Keep repair and diagnostics conservative: explicit confirmation for destructive actions, short retention, and sanitized output only.

### P2: NodeBB User Profile Controls

- Added a user-facing read-only linked-account page at `/user/<userslug>/authentik-oidc`.
- Added a self-only profile menu link for the linked-account page.
- Added ACP-configurable Authentik self-service links for profile, password, MFA, and sessions.
- Exposed only safe link metadata: linked status, provider display name, issuer, link/login timestamps, last provider email, managed-field status, and configured external actions.
- Do not let users edit identity-critical OIDC state from NodeBB. `sub`, issuer, and verified-email link mappings remain admin/plugin controlled.
- Deferred refresh and disconnect controls until the OIDC flow can enforce the stored linked `sub` for those actions.

### P3: Profile Synchronization

- Added opt-in display name synchronization from OIDC `name` to NodeBB `fullname` after identity resolution.
- Keep further sync disabled by default or limited to low-risk fields until diagnostics and conflict policies are solid.
- Treat email sync and username sync as higher-risk than display name/avatar sync because they affect account recovery, mentions, and user recognition.

### P4: Authentik-Side Enrollment Polish

- Document Authentik flow/policy recipes for duplicate username/email rejection, required email, claim mapping, account selection, and external profile management.
- Add optional deep links from NodeBB to Authentik self-service flows, but do not make the NodeBB plugin depend on Authentik admin APIs for core login.

## Release Blockers

- Verify both username-collision ACP policies live: `unique` should create a safe unique NodeBB username, and `reject` should fail new SSO account creation without creating a user or mapping.
- Capture actual OIDC claims for an Authentik account intended to be unverified. The live test is not complete until the emitted `email_verified` claim is confirmed to be boolean `false`.
- Investigate the post-callback hang seen after repeat login. Confirm whether NodeBB is waiting on a response, redirecting to an interstitial, or completing login with a frontend routing issue.
- Confirm stale `authentik:sub:uid` cleanup in live data by deleting a mapped test user and retrying with the same Authentik subject.

## Plugin Hardening

- Security audit tightened outbound URL validation, JWKS signing-key selection, unsafe self-service link filtering, missing-state handling, and provider error callbacks.
- Expand sanitized diagnostics if live failures need more context. Current ACP diagnostics include rejection code, claim presence, `email_verified` type/value, issuer metadata, and whether userinfo was used; raw tokens and full claims are not stored.
- Logout/session-revocation follow-up:
  - Live-test Authentik back-channel logout with ACP Last logout diagnostics after rebuilding NodeBB.
  - Confirm Authentik sends a POST with `logout_token` for user logout and administrative session deletion.
  - Support OIDC RP-initiated logout from NodeBB to Authentik where practical.
  - Add an ACP action to revoke all NodeBB sessions for a linked uid/sub if live operations need manual intervention.
- Live-test admin-configurable authorization parameters for Authentik flows, especially `prompt=login` or `prompt=select_account`, to reduce accidental reuse of an existing Authentik browser session.
- Decide which username-collision policy to recommend for first release:
  - `unique`: create a safe unique NodeBB username for new SSO users.
  - `reject`: fail new SSO account creation when NodeBB reports the username/userslug is unavailable.
- Extend the new ACP mapping audit/repair tooling with CLI access if live operations need non-browser repair.
- Add tests around NodeBB's userslug collision behavior, not only exact username matching.
- Consider DNS resolution checks before outbound discovery/JWKS fetches to catch hostnames that resolve to private IP addresses.

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
  - Display name sync: implemented as an opt-in update from `name` to `fullname` after identity resolution.
  - Avatar sync: update NodeBB avatar from OIDC `picture` only if enabled and URL passes validation.
  - Custom field sync: map explicit OIDC claim names to NodeBB user fields.
- Add role/group attachment synchronization as a separate, explicit subsystem:
  - Map NodeBB groups to Authentik groups or roles through an ACP table.
  - Support direction per mapping: Authentik to NodeBB, NodeBB to Authentik, or bidirectional.
  - Example: membership in the NodeBB `Developers` group grants the Authentik `developers` role; leaving the NodeBB group removes that role when the mapping is configured as NodeBB-owned.
  - Example: receiving an Authentik `developers` role/group claim adds the user to the NodeBB `Developers` group when the mapping is configured as Authentik-owned.
  - Keep each mapping explicit: NodeBB group name/id, Authentik role/group identifier, direction, ownership policy, removal behavior, priority, and enabled flag.
  - Require an Authentik management API token only for NodeBB to Authentik writes; OIDC login claims are enough only for Authentik to NodeBB reads.
  - Add dry-run previews showing role/group additions and removals for a uid/sub before applying writes.
  - Store per-user role sync audit fields such as `authentikLastRoleSyncedAt`, last applied mapping version, and last role sync status.
  - Prevent sync loops with source-of-truth ownership, mapping versions, and a "do not echo remote changes back" rule for the same sync pass.
  - Treat privileged groups as high-risk: require explicit confirmation before mappings affect admin/moderator or Authentik administrative roles.
- Store sync audit fields on each user: `authentikLastSyncedAt` is implemented for display name sync; add `authentikLastUsername` and per-field sync status when practical.
- Make synchronization happen after identity resolution by `sub`, never before identity resolution.
- Treat synchronization failures as field-level warnings by default, not login failures, except for email conflicts or identity-critical fields.
- Add dry-run diagnostics in ACP showing what profile fields and role/group attachments would change for a selected uid/sub without applying writes.
- Add tests for changed email, username conflict, avatar URL validation, missing claims, custom field mapping, local user edits being overwritten only when sync is enabled, role/group mapping direction, removal behavior, loop prevention, and privileged-role guardrails.

## ACP Configuration And UX

- Rework the ACP page into clear sections:
  - Provider connection: enabled, display name, issuer, discovery, endpoints, JWKS URI, client id, client secret, scopes, callback URL.
  - Login behavior: authorization parameters, PKCE toggle, HTTPS development override, local login policy, and the existing account creation policy.
  - Identity rules: verified-email requirement, username collision policy, email collision behavior, stale mapping cleanup behavior.
  - Synchronization: per-field sync toggles for email, username, fullname, avatar, custom claim mappings, and role/group attachment mappings.
  - Diagnostics and repair: test discovery, test provider connection, inspect sanitized last failure, audit mappings, repair stale mappings.
- Add switches and levers:
  - Enable/disable plugin.
  - Use PKCE.
  - Allow insecure callback URL for local development only.
  - Force account selection/fresh Authentik login via preset authorization parameters.
  - Account creation policy is implemented; improve its confirmation/field grouping in the ACP.
  - Username collision policy: generate unique, keep existing/local, or reject.
  - Sync toggles: display name is implemented; email, username, avatar, and custom fields remain deferred.
  - Role/group attachment table: NodeBB group, Authentik role/group, direction, ownership/removal policy, priority, and enabled flag.
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
  - "Dry-run sync" shows what profile fields and role/group attachments would change for a selected uid or `sub`.
- Add safety guardrails:
  - Require confirmation before enabling account creation, destructive repair actions, or sync modes that overwrite local profile fields.
  - Require confirmation before enabling bidirectional role sync or mappings that touch NodeBB privileged groups or Authentik administrative roles.
  - Do not display raw client secret, tokens, authorization codes, ID tokens, or full claim payloads in ACP.
  - Mark development-only settings clearly and keep them disabled by default.
- Add ACP tests or fixtures for save/reload, placeholder secret preservation, discovery preview, validation errors, toggles, and diagnostics endpoints.

## User Profile OIDC Controls

Implemented:

- Add a NodeBB user account page for linked accounts that initially shows only safe information:
  - Linked status.
  - Provider display name.
  - Linked issuer.
  - Linked timestamp.
  - Last login time.
  - Last provider email seen.
  - Which local fields are managed by Authentik sync.
- Add ACP-configurable URLs for external Authentik profile, password, MFA, and session actions.
- Add a self-only profile menu entry.
- Keep `authentikSub` and reverse mapping keys server-side only.

Remaining:

- Last sync time is shown when display name synchronization runs.
- Show whether the current NodeBB email is provider-verified once email sync policy exists.
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
