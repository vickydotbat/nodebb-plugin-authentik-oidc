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

- Added [Authentik setup and enrollment hardening](AUTHENTIK_SETUP.md) with operator recipes for required email, `email_verified` claim mapping, duplicate username/email rejection, account selection, external self-service links, and back-channel logout.
- Added optional deep links from NodeBB to Authentik self-service flows, without making the NodeBB plugin depend on Authentik admin APIs for core login.

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

- Added default fresh-provider-login authorization parameters to reduce Authentik browser-session reuse during enrollment and linking.
- Added a regression test confirming new SSO-created users do not inherit `picture`, `uploadedpicture`, `icon:text`, or `icon:bgColor` from an existing NodeBB account.
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
- Add an Authentik cleanup/recovery policy for inactive users left behind by expired email verification during enrollment, since they can reserve usernames and block retry registration until manually deleted or recovered.
- Confirm the Authentik provider maps the real email verification state into the OIDC `email_verified` claim.
- Consider forcing account selection or fresh login for the NodeBB provider flow if browser sessions make the wrong Authentik account visually appear during registration.
- Configure Authentik to emit only intended profile claims for NodeBB, including `preferred_username`, `name`, `email`, `email_verified`, and optionally `picture`.
- Decide whether Authentik should prevent profile changes locally in NodeBB by policy, UI messaging, or future plugin settings.

## Final Roadmap: Authentik As Source Of Truth

This is the end-state roadmap for replacing NodeBB-native identity with Authentik while still preserving safe migration for existing NodeBB accounts.

### Goal

- Authentik becomes the primary identity system for login, registration, logout, password changes, email changes, username/profile changes, MFA, consent, and session management.
- NodeBB keeps local accounts and uids as application records, but identity operations are delegated to Authentik.
- Existing NodeBB users can migrate without duplicate NodeBB accounts and without username-based takeover.
- Local NodeBB login remains available only during migration or as an explicit break-glass path. The final security mode must be able to disable NodeBB-native login completely for normal users so Authentik-owned MFA cannot be bypassed.

### Feasibility Boundary

Just-in-time migration from a NodeBB username/password into Authentik is not possible through OIDC alone. OIDC starts after Authentik has authenticated the user, so the NodeBB plugin does not receive the user's old NodeBB password during the Authentik login flow.

The safe options are:

1. Recommended: bulk pre-provision Authentik users from NodeBB data, then link on first OIDC login by verified email or a controlled migration identifier.
2. Possible with more work: create an Authentik-side migration flow/source that validates old NodeBB credentials against a narrowly scoped NodeBB migration endpoint, then creates the Authentik user inside Authentik.
3. Possible but higher risk: let the NodeBB plugin expose a one-time authenticated migration wizard for already logged-in NodeBB users that creates an Authentik account through the Authentik API and immediately links it.

The plugin must not implement a generic form that collects NodeBB passwords and blindly creates Authentik accounts without rate limits, audit logs, CSRF protection, and replay protection.

### Track A: Existing Account Migration

#### A1. Data Inventory

- Add an ACP migration audit page:
  - total NodeBB users
  - users already linked to Authentik
  - users with confirmed email
  - users without email
  - users with duplicate email
  - users with unconfirmed email
  - users with local password credentials
  - privileged users: admins, global moderators, category moderators
- Add CSV/JSON export for migration planning without password hashes by default.
- Add an optional dry-run report that checks whether each NodeBB email already exists in Authentik, using a least-privilege Authentik API token.

#### A2. Authentik Management API Integration

- Add ACP settings for Authentik admin API access:
  - base URL
  - API token
  - default group for migrated users
  - default active/inactive state
  - whether migrated users must reset password before first login
  - whether email should be marked verified only when NodeBB email is confirmed
- Store the API token as a secret and never return it in ACP JSON.
- Add "Test Authentik API" diagnostics that verifies token scope without exposing the token.
- Use the Authentik API only for migration and profile-management actions, never for OIDC login identity decisions.

#### A3. Recommended Bulk Pre-Provision Mode

- Add dry-run pre-provision:
  - match NodeBB users to Authentik users by normalized verified email only
  - flag duplicate emails on either side
  - flag username conflicts separately from identity matching
  - flag missing/unverified email users as not eligible
- Add execute pre-provision:
  - create Authentik users for eligible NodeBB accounts that do not already exist
  - set username from NodeBB username after Authentik-safe normalization
  - set email from NodeBB confirmed email
  - assign migration group
  - require password reset or send enrollment/recovery link rather than copying password hashes
  - write a pending migration marker on NodeBB: `user:<uid>.authentikMigrationPending = true`
- On first successful OIDC login:
  - resolve by `sub` if already linked
  - otherwise link by verified email to the existing NodeBB uid
  - clear `authentikMigrationPending`
  - record `authentikMigratedAt`

#### A4. Authentik-Side Just-In-Time Migration Mode

This is possible only if Authentik runs the old-credential check before OIDC completes.

- Create a dedicated Authentik enrollment/authentication flow for "Migrate NodeBB account":
  - identification stage for username/email
  - password stage or custom source/backend that validates against NodeBB
  - email verification stage when needed
  - user write stage to create/update the Authentik user
  - user login stage to attach the Authentik session
- Add a NodeBB migration verification endpoint only if needed by that Authentik flow:
  - accepts username/email + password over HTTPS only
  - rate-limited and logged
  - validates against NodeBB's existing password verifier
  - returns only a signed short-lived migration assertion, not user data or password hashes
  - disables itself after migration window closes
- Authentik consumes the migration assertion and creates the Authentik user.
- NodeBB receives normal OIDC claims and links by verified email or a migration claim.
- Do not let a NodeBB username alone become authority. Require either verified email continuity or a signed migration assertion tied to the exact uid.

#### A5. NodeBB-Side Self-Service Migration Wizard

This is useful for users who can still log into NodeBB locally before SSO becomes mandatory.

- Add ACP toggle: "Allow logged-in users to create/link Authentik account".
- Add `/user/<slug>/authentik-oidc/migrate` for self only.
- Require current NodeBB password re-authentication for local accounts before migration.
- Let the user choose:
  - create Authentik account with current confirmed NodeBB email
  - link to existing Authentik account by starting OIDC login
  - send Authentik enrollment/recovery email
- Create or invite the Authentik user through the Authentik API.
- Force first Authentik login before writing the permanent `sub` mapping.
- Log all migration attempts with uid, status, and reason, but no passwords or tokens.

#### A6. Migration Guardrails

- Do not migrate users with missing email until they add and verify one.
- Do not auto-migrate duplicate emails.
- Do not auto-migrate privileged users without explicit admin confirmation.
- Do not copy NodeBB password hashes into Authentik unless a reviewed Authentik-compatible import path exists and the algorithm mapping is explicitly tested.
- Keep a rollback path:
  - local login fallback for admins
  - ability to disable forced SSO
  - ability to unlink an Authentik mapping only when a safe fallback login exists
  - migration audit export before and after writes

### Track B: ACP Levers To Replace NodeBB Identity UI

#### B1. Login And Registration Routing

- Add ACP section: "Identity ownership".
- Add toggles:
	- Show Authentik login button only
	- Redirect `/login` to `/auth/authentik`
	- Redirect `/register` to Authentik enrollment URL
	- Disable NodeBB local registration
	- Hide NodeBB local login form
	- Disable NodeBB local login POST/API for normal users
	- Disable NodeBB password reset/recovery flows for normal users
	- Keep emergency local admin login route enabled
	- Require Authentik for non-admin users
- Security rationale: hiding the local login form is not enough. If Authentik owns MFA, local NodeBB username/password authentication must be blocked server-side, otherwise users can bypass MFA by posting directly to NodeBB login endpoints.
- Implement with NodeBB hooks/routes where available:
	- override login page rendering or redirect unauthenticated `/login`
	- redirect `/register` and registration CTA links
	- block local login POST/API behavior by policy, not only by hidden UI
	- block local password reset and local password-change flows when Authentik manages passwords
- Add emergency route such as `/login/local-admin`:
	- disabled unless explicitly enabled
	- restricted to explicitly allowlisted admin uids or groups
	- unavailable to normal users even if they know the URL
	- rate-limited
	- optionally restricted by IP allowlist or reverse-proxy auth
	- logs every attempt and successful use as a security event
	- documented as break-glass access

#### B2. Logout Routing

- Add ACP setting: "NodeBB logout behavior".
- Modes:
  - NodeBB only: current local logout behavior
  - Authentik application logout: redirect to provider end-session URL
  - Full Authentik logout: redirect to a configured Authentik invalidation flow that logs out all apps
- Implement RP-initiated logout:
  - discover/use `end_session_endpoint` when available
  - pass `id_token_hint` only if the plugin later stores a safe short-lived usable value; otherwise avoid token storage
  - pass `post_logout_redirect_uri` only when registered in Authentik
  - clear NodeBB session before redirecting to Authentik
- Document Authentik requirement:
  - `default-provider-invalidation-flow` logs out only the application by default
  - full SLO from app logout requires an invalidation flow with User Logout stage or equivalent Authentik configuration

#### B3. Profile Edit Routing

- Expand existing self-service URL settings into explicit managed-action settings:
  - Authentik profile URL
  - change email flow URL
  - change username/profile flow URL
  - change password flow URL
  - MFA/devices flow URL
  - sessions flow URL
  - consent/app grants URL
- Add ACP toggles:
  - Authentik manages email
  - Authentik manages username
  - Authentik manages display name
  - Authentik manages password
  - Authentik manages MFA
  - Authentik manages avatar
- On `/user/<slug>/edit`, add read-only managed-field notices and action buttons to Authentik.
- Where NodeBB provides field-specific hooks, disable local edits for managed fields.
- Where NodeBB does not provide field-specific hooks, intercept update APIs server-side and reject writes to managed fields with a clear error.
- Keep NodeBB-owned settings editable:
  - notification preferences
  - digest preferences
  - forum UI preferences
  - signatures/about-me only if not mapped from Authentik

#### B4. Email, Username, And Password Policy

- Email:
  - Authentik is source of truth only when `email_verified === true`.
  - NodeBB email changes should be blocked when Authentik manages email.
  - On login, email sync can update NodeBB only if the target email is not used by another uid.
- Username:
  - Authentik `preferred_username` may update NodeBB username only if explicitly enabled.
  - Username conflicts fail sync, not login, unless admin marks it login-critical.
  - Username never affects identity mapping.
- Password:
  - Disable local password change UI when Authentik manages passwords.
  - Existing local passwords remain only for emergency fallback until the admin explicitly disables local login.
  - Do not try to keep NodeBB and Authentik passwords synchronized.

#### B5. ACP UX And Rollout Modes

- Add rollout presets:
	- Mixed mode: local login/register visible, Authentik available
	- Migration mode: Authentik preferred, local login fallback visible
	- SSO required: `/login` and `/register` redirect to Authentik, local fallback hidden, local login API still available only if explicitly allowed
	- SSO enforced: NodeBB local login, registration, password reset, and password change are blocked for normal users
	- SSO enforced plus break-glass: same as SSO enforced, with a tightly scoped emergency local admin route
	- SSO enforced without break-glass: all NodeBB-native authentication is disabled; recovery requires server/database access or disabling the plugin out of band
- Each preset should show exactly which toggles it changes.
- Require typed confirmation before enabling SSO enforced mode.
- Run preflight checks before allowing SSO enforced mode:
	- at least one admin has linked Authentik
	- at least one admin has working Authentik MFA
	- back-channel logout configured or consciously skipped
	- Authentik discovery/JWKS test passes
	- redirect URI and logout URI match NodeBB public URL
	- emergency admin fallback decision recorded
	- admin confirms that NodeBB-native login bypasses Authentik MFA and will be blocked for normal users

#### B6. Testing Plan

- Migration:
  - eligible local user pre-provisions into Authentik and links on first OIDC login
  - duplicate email blocks migration
  - missing/unverified email blocks migration
  - privileged user requires explicit confirmation
  - existing Authentik account with verified matching email links to existing NodeBB uid
  - migration API failures do not change NodeBB mappings
  - migration cannot be replayed with a stale assertion
- SSO replacement:
	- `/login` redirects to Authentik when enabled
	- `/register` redirects to Authentik enrollment when enabled
	- emergency admin login remains reachable when configured
	- local login POST/API is rejected for normal users in SSO enforced mode
	- local password reset/recovery is rejected for normal users in SSO enforced mode
	- local password change is rejected when Authentik manages passwords
	- local login cannot bypass Authentik MFA for normal users
	- local registration POST/API is blocked, not only hidden
	- managed email/username/password edits are blocked server-side
	- unmanaged profile preferences remain editable
  - logout redirects to Authentik and clears NodeBB session
  - Authentik back-channel logout still revokes NodeBB sessions

## Live Cleanup

- Remove accidental duplicate NodeBB users created during testing.
- Remove or repair stale `authentik:sub:uid` mappings for deleted test users.
- Audit users with `authentikSub` and confirm each has exactly one matching entry in `authentik:sub:uid`.
- Audit test Authentik users with missing email or duplicate emails and remove them once provider-side policies are in place.
