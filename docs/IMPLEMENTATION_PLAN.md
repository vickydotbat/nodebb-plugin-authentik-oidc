# nodebb-plugin-authentik-oidc Implementation Plan

## Purpose

Build a minimal, maintained NodeBB plugin that supports Authentik and standards-compliant OAuth2/OIDC providers without weakening account identity rules. The plugin's defining requirement is deterministic identity linking:

- `sub` is the only permanent external identity.
- Verified email can link an unlinked provider identity to an existing NodeBB account.
- Username is never used for identity matching.
- Claim conflicts fail closed instead of creating a second account or taking over an account.

## Current Repository State

The repository now contains the first working plugin implementation:

- NodeBB plugin manifest, auth strategy registration, ACP route registration, and admin navigation.
- Direct OAuth2/OIDC code flow with state, nonce, optional PKCE, ID token validation, userinfo retrieval, and issuer/audience validation.
- Strict identity resolution by `sub` with verified-email linking, stale mapping cleanup, collision rejection, and create-time username retry handling.
- ACP settings with discovery, secret-preserving saves, authorization parameters, username collision policy, sanitized last-failure diagnostics, JWKS health checks, mapping audit, stale mapping repair, and optional Authentik self-service URLs.
- Optional OIDC back-channel logout support that validates signed logout tokens and revokes NodeBB sessions by linked `sub` or stored OIDC `sid`.
- A self-only user account page that shows linked-account state and configured external Authentik self-service actions without exposing OIDC subjects or mapping keys.
- Automated unit tests for identity safety, discovery issuer handling, authorization parameter handling, diagnostics sanitization, JWKS checks, username generation, mapping audit/repair, and user-facing linked-account state.

Remaining release work is mostly live verification against the target NodeBB/AuthentiK environment, profile synchronization design, and operator documentation polish.

## Standing Rule: ACP Exposure For Explicit Toggles

Every implementation phase must treat ACP exposure as part of the definition of done for any new explicit setting, policy switch, redirect mode, or debug/operational lever.

- Do not leave hardcoded booleans or runtime behavior flags in code when they are meant to be adjusted during troubleshooting, migration, or live verification.
- If a setting is declared in `lib/config.js` or introduced as a new runtime behavior switch, add the ACP control, save/load wiring, validation, and tests in the same step.
- If a lever is intentionally not exposed in the ACP, document the reason in code or docs so the omission is deliberate and reviewable.
- Apply this rule continuously, not as a later ACP cleanup phase.

## Confirmed NodeBB Conventions

Current NodeBB plugin documentation confirms these conventions:

- A plugin is discovered through `plugin.json`.
- `plugin.json` declares a `library` entrypoint, hooks, templates, scripts, ACP scripts, static directories, and language assets.
- Server code normally registers routes from a `static:app.load` hook.
- ACP routes should use NodeBB route helpers where available.
- Admin navigation is added through a plugin hook and rendered as an ACP page.
- NodeBB server APIs are accessed from plugins through `require.main.require(...)`.
- NodeBB requires an asset build after plugin activation or frontend/admin asset changes.
- NodeBB tests can run through the NodeBB test harness with `test_plugins` configured.

Implementation must still validate exact hook names and method signatures against the local target NodeBB version before the first release, especially the authentication strategy hook, admin header hook, and user email APIs.

## Proposed Package Shape

```text
nodebb-plugin-authentik-oidc/
  package.json
  plugin.json
  library.js
  lib/
    admin.js
    config.js
    discovery.js
    errors.js
    identity.js
    oidc.js
    routes.js
    state.js
    username.js
  public/
    admin.js
  templates/
    admin/plugins/authentik-oidc.tpl
  languages/
    en-GB/authentik-oidc.json
  test/
    identity.test.js
    username.test.js
    fixtures/
      authentik-userinfo.verified.json
      authentik-userinfo.unverified.json
      authentik-userinfo-missing-email.json
  docs/
    IMPLEMENTATION_PLAN.md
    SECURITY.md
    TEST_CHECKLIST.md
```

Keep the runtime small. Prefer Node's built-in `fetch`, `crypto`, and `URL` APIs where supported by the NodeBB-supported Node.js version. Add dependencies only when they materially improve protocol correctness.

## OIDC Library Decision

Evaluate three options before coding the login flow:

1. Direct implementation with Node built-ins
   - Pros: smallest dependency surface, straightforward Authentik support, easy to audit.
   - Cons: easy to miss OIDC edge cases such as JWKS rotation, nonce validation, token hash checks, and discovery quirks.

2. `openid-client`
   - Pros: mature OIDC semantics, discovery, issuer validation, token validation, JWKS handling.
   - Cons: dependency surface, version/API compatibility must match NodeBB's supported Node runtime and module format.

3. `passport-openidconnect`
   - Pros: fits older NodeBB SSO plugin patterns.
   - Cons: Passport abstractions can hide important conflict handling, may encourage profile-based identity assumptions, and adds less value if custom identity resolution is required.

Preferred direction: use `openid-client` if its current major version is compatible with the target NodeBB runtime and CommonJS/plugin loading model. If not, implement direct OAuth2 code exchange plus explicit ID token verification using `jose`. Avoid `passport-openidconnect` unless NodeBB's current SSO strategy flow makes Passport registration significantly simpler and auditable.

## NodeBB Integration Plan

### Manifest

`plugin.json` should define:

- Plugin id: `nodebb-plugin-authentik-oidc`.
- Server library: `./library.js`.
- `static:app.load` hook for route setup.
- Admin navigation hook, expected to be `filter:admin.header.build`.
- Authentication strategy/list hook, to be confirmed against current NodeBB.
- User data whitelist hook for custom user fields, if current NodeBB still requires this for custom fields on deletion/export.
- ACP script and admin template.
- Language path.

### Server Entrypoint

`library.js` should be thin:

- Load NodeBB modules.
- Expose hook methods.
- Register `/auth/authentik` and `/auth/authentik/callback`.
- Register admin page and admin API routes.
- Register the login button/strategy metadata if the current NodeBB auth hook supports it.
- Delegate protocol, config, and identity logic to `lib/*`.

### Login Routes

Routes:

- `GET /auth/authentik`
- `GET /auth/authentik/callback`

Login start should:

- Load and validate settings.
- Build the callback URL from NodeBB's configured public URL.
- Reject insecure public callback URLs unless an explicit development override is enabled.
- Generate `state`.
- Generate `nonce` when ID token validation is used.
- Optionally generate PKCE verifier/challenge if supported by the provider and chosen library.
- Store state data server-side in the user's session with an expiry.
- Redirect to the authorization endpoint with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, and `nonce`.

Callback should:

- Validate the request has `code` and `state`.
- Validate `state` exists, matches, is unexpired, and is single-use.
- Exchange the code using client authentication appropriate for confidential clients.
- Validate token response shape.
- Validate issuer.
- Validate ID token when present.
- Retrieve userinfo when configured or required by missing claims.
- Normalize claims.
- Resolve or create the NodeBB user through the identity module.
- Call NodeBB's successful-login handler/session flow.
- Redirect to the originally requested destination only after validating it is local.

## Identity Resolution Algorithm

Inputs:

- `sub` string, required and non-empty.
- `email` string, required and normalized.
- `email_verified` boolean, required.
- `preferred_username` optional display seed.
- `name` optional full name.
- Provider issuer and client id from validated settings.

Storage:

- `authentik:sub:<sub>.uid -> uid`
- `authentik:sub:uid[<sub>] -> uid` for auditable object-field scans and compatibility with the ACP repair tooling
- `user:<uid>.authentikSub = <sub>`
- `user:<uid>.authentikIssuer = <issuer>`
- `user:<uid>.authentikLinkedAt = <ISO timestamp or epoch ms>`
- Optional audit fields:
  - `user:<uid>.authentikLastLoginAt`
  - `user:<uid>.authentikLastEmail`
  - `authentik:sid:uid` object-field mapping from OIDC `sid` to uid for back-channel logout when the provider emits `sid`

Resolution steps:

1. Validate `sub`. Reject if missing.
2. Lookup `subUid` from `authentik:sub:uid[<sub>]` and the direct `authentik:sub:<sub>.uid` key. If both exist and disagree, fail safely because the identity mapping storage is inconsistent.
3. If `subUid` exists:
   - Confirm the NodeBB user still exists.
   - Do not require current email to match the mapped user's email.
   - If the current verified email belongs to another uid, reject and log `sub/email collision`.
   - Otherwise login `subUid`.
4. If no `subUid`:
   - Reject if `email` is missing.
   - Reject if `email_verified !== true`.
   - Lookup `emailUid = user.getUidByEmail(email)`.
   - If `emailUid` exists:
     - Confirm `emailUid` does not already have a different `authentikSub`.
     - Write the sub mapping to `emailUid`.
     - Login `emailUid`.
   - If no `emailUid`:
     - Generate a safe unique username from `preferred_username`, `name`, or email local part.
     - Create a new NodeBB user.
     - Set email.
     - Confirm email only because `email_verified === true`.
     - Write the sub mapping.
     - Login the new uid.

Conflict rules:

- Existing `sub` mapping wins over email continuity, except when the current verified email maps to a different NodeBB uid. That specific condition fails closed because it can indicate provider subject reassignment, email reuse, stale mapping, or attempted takeover.
- Existing user with matching email but existing different `authentikSub` fails closed.
- Any database write failure during create/linking must fail the login and leave enough logs for repair.
- If user creation succeeds but mapping fails, log an error and reject. Add an operational repair note because this creates an unlinked local user; the next implementation phase should reduce this risk with rollback or a pending-link marker where practical.

## Email Handling

- Normalize email consistently before lookup and storage.
- Treat `email_verified` as valid only when it is the boolean `true`; do not treat `"true"`, `1`, or absent values as verified unless documented provider behavior requires a deliberately reviewed compatibility option.
- Reject missing email for all new/unlinked identities.
- For existing `sub` mappings, login may continue if the provider omits email only if a future admin setting explicitly allows it. Initial release should reject missing email for all callbacks to satisfy the primary requirement.
- Never mark email confirmed when `email_verified` is false, missing, or non-boolean.

## Username Handling

Username is display-only and account-creation-only:

- Preferred seed order: `preferred_username`, `name`, email local part, `authentik-user`.
- Sanitize through NodeBB's username rules if exposed by current APIs.
- Never match an existing account by username.
- On collision, append a stable or random suffix.
- Avoid leaking `sub` in usernames.
- Ensure generated usernames are not reserved, empty, too long, or made entirely invalid by sanitization.

## Admin Settings

Fields:

- `enabled`
- `clientId`
- `clientSecret`
- `issuer`
- `authorizationEndpoint`
- `tokenEndpoint`
- `userinfoEndpoint`
- `scopes`, default `openid email profile`
- `callbackUrl`, computed read-only
- `backchannelLogoutEnabled`, default false
- `backchannelLogoutUrl`, computed read-only
- `allowInsecureCallbackUrlForDevelopment`, default false
- `displayName`, default `Authentik`
- Optional future fields:
  - `requireHttpsIssuer`, default true
  - `usePkce`, default true if supported
  - `discoveryEnabled`, default true
  - `syncFullName`, default false
  - `syncAvatar`, default false

Admin save behavior:

- Load settings through NodeBB's current settings API.
- Save through the current ACP settings helper or a protected plugin API route.
- Do not return the saved `clientSecret` in normal settings payloads.
- Use a placeholder such as `********` in the UI when a secret is configured.
- Preserve the existing secret when the admin leaves the secret field blank.
- Replace the secret only when a non-placeholder value is submitted.
- Validate URLs before saving.
- Validate issuer and discovery document when discovery is requested.
- Show field-level validation errors for missing or malformed config.

Admin API routes:

- `GET /api/admin/plugins/authentik-oidc/settings`
- `POST /api/admin/plugins/authentik-oidc/settings`
- `POST /api/admin/plugins/authentik-oidc/discover`
- Optional: `POST /api/admin/plugins/authentik-oidc/validate`

All admin API routes must require logged-in admin privileges and CSRF protection consistent with current NodeBB route helpers.

## OIDC Discovery

Discovery from issuer should:

- Fetch `/.well-known/openid-configuration`.
- Require HTTPS issuer unless development override is enabled.
- Validate the returned `issuer` exactly matches configured issuer after documented normalization.
- Populate authorization, token, userinfo, and JWKS endpoints.
- Verify required capabilities:
  - Authorization code flow.
  - `openid` scope support where advertised.
  - Token endpoint auth method compatible with confidential client secret.
- Cache discovery metadata for a short duration at runtime.
- Refresh on settings save or cache expiry.
- Log discovery failures without logging secrets.

## Token And Claim Validation

Minimum validation:

- Authorization callback state.
- Issuer.
- Audience/client id.
- Expiration.
- Not-before/issued-at tolerance if applicable.
- Nonce when ID token is used.
- Required claims.
- `sub` type and length.
- `email` type and reasonable length.
- `email_verified` exact boolean semantics.

Recommended validation:

- Use Authorization Code flow only.
- Use PKCE even for confidential clients if supported.
- Validate ID token signature with JWKS.
- Validate `at_hash` if relying on access token from ID token.
- Prefer userinfo claims for current email/profile details but require `sub` consistency between ID token and userinfo when both are present.
- Reject if userinfo `sub` differs from ID token `sub`.
- Reject token/userinfo responses with non-JSON content where JSON is required.
- Use conservative HTTP timeouts.

## Session, State, CSRF, And Redirect Safety

- Store state server-side in session, not only in a signed client cookie.
- State entries should include created time, nonce, redirect destination, and optional PKCE verifier.
- Delete state after first callback use.
- Expire state after a short window, such as 10 minutes.
- Limit outstanding states per session to prevent session growth.
- Callback `next`/destination must be local-only. Reject absolute external URLs.
- Admin POST routes must use NodeBB's CSRF/admin middleware.
- Login routes should not change settings or user mappings before callback validation completes.
- Back-channel logout route must be unauthenticated and CSRF-exempt enough for Authentik server-to-server POSTs, but must validate signed OIDC logout tokens before revoking any NodeBB session.
- Back-channel logout is disabled by default. When enabled, it should revoke NodeBB sessions only after mapping the logout token's `sub` or `sid` to a linked uid.

## HTTPS And Proxy Concerns

- Compute callback URL from NodeBB's configured public URL, not raw request headers, unless current NodeBB exposes a trusted helper.
- Require public callback URL scheme `https` by default.
- Allow `http://localhost` and `http://127.0.0.1` only in development mode.
- Document reverse proxy requirements for correct NodeBB public URL.
- Do not trust arbitrary `X-Forwarded-*` headers directly.

## Logging Plan

Use NodeBB/Winston logging with a stable prefix: `[plugin/authentik-oidc]`.

Info:

- Login by existing `sub`.
- Linked existing user by verified email.
- Created new user from verified OIDC identity.
- Discovery succeeded.
- Settings updated, excluding secret values.

Warn:

- Missing email.
- Unverified email for unlinked identity.
- Sub/email collision.
- Existing user has a different linked sub.
- Provider returned malformed, incomplete, or inconsistent claims.
- Insecure callback URL rejected.

Error:

- Token exchange failure.
- ID token validation failure.
- Userinfo request failure.
- Database mapping write failure.
- NodeBB user creation/update failure.

Never log:

- Client secret.
- Authorization code.
- Access token.
- Refresh token.
- Full ID token.
- Raw userinfo body when it could include sensitive claims.

## Security Hardening Checklist

- Use code flow only.
- No implicit flow support.
- Validate state and nonce.
- Enforce exact issuer match.
- Enforce exact audience/client id match.
- Require verified email for all new links and new accounts.
- Never link by username.
- Never silently resolve collisions.
- Enforce HTTPS public callback URL outside development.
- Do not expose saved client secret in ACP payloads.
- Ensure admin routes require admin privileges.
- Use local-only post-login redirects.
- Set HTTP request timeouts for discovery, token, and userinfo calls.
- Restrict accepted response content types.
- Bound input lengths for issuer, endpoints, client id, username seeds, `sub`, and email.
- Add dependency audit workflow before release.
- Add operational instructions for rotating client secrets and repairing mappings.

## Fringe Cases To Handle

- Provider changes email after account is linked.
- Provider returns same email with uppercase/lowercase differences.
- Provider returns `email_verified` as a string.
- Provider returns no userinfo endpoint.
- Provider returns `sub` in ID token and different `sub` in userinfo.
- Provider returns `preferred_username` that is already taken.
- Provider returns `preferred_username` with disallowed characters.
- Existing NodeBB account email differs only by case.
- Existing NodeBB account has unconfirmed local email but provider email is verified.
- Existing NodeBB user has a different `authentikSub`.
- Sub mapping points to deleted uid.
- Two callbacks race for the same unlinked `sub`.
- Two callbacks race for the same verified email.
- Database write succeeds for user field but fails for reverse mapping.
- Admin clears the secret unintentionally.
- Admin changes issuer after users are linked.
- NodeBB runs behind a proxy with mismatched public URL.
- Authentik application is configured with the wrong redirect URI.
- Authentik sends groups/roles claims that this plugin ignores in the first release.
- Local login remains enabled and user later changes local email.

## Race And Consistency Strategy

NodeBB database primitives may not provide full transactions across all supported databases. The identity module should therefore:

- Re-check mappings immediately before writing.
- Write the reverse mapping and user fields in a consistent order.
- Treat duplicate-key or changed-state outcomes as conflicts.
- Prefer idempotent writes where the mapping already points to the same uid.
- Add focused tests for concurrent login attempts if the test harness can simulate them.
- Document manual repair commands only for exceptional administrator recovery, not normal operation.

If current NodeBB database APIs support locks or sorted-set/object-field compare-and-set behavior, use them. Otherwise, implement conservative double-checks and fail closed when the post-write state is inconsistent.

## Testing Plan

Unit tests should cover identity logic without making network calls:

1. New verified OIDC user creates exactly one NodeBB user and one sub mapping.
2. Same `sub` repeatedly resolves to the same uid.
3. Existing NodeBB user with same verified email links without duplicate creation.
4. Same email with `email_verified=false` rejects when no sub mapping exists.
5. Username conflict with different email creates a safe unique username.
6. Existing `sub` with changed email still resolves by sub.
7. `sub` mapped to uid A but verified email belongs to uid B rejects.
8. Missing email rejects.
9. Existing email user with different linked sub rejects.
10. Userinfo `sub` and ID token `sub` mismatch rejects.
11. String `"true"` for `email_verified` rejects unless compatibility mode is later added.
12. Mapping write failure rejects and logs an error.

Admin tests should cover:

- Settings save/reload.
- Blank secret preserves existing secret.
- Placeholder secret does not overwrite existing secret.
- New secret replaces existing secret.
- Discovery populates endpoints.
- Invalid issuer/discovery reports validation errors.
- Non-admin cannot read or write settings.

Manual integration tests should cover:

- Authentik authorization code login.
- Wrong callback URL.
- Wrong client secret.
- Wrong issuer.
- User deleted in NodeBB after mapping exists.
- NodeBB behind reverse proxy.
- Plugin activation, build, restart, disable, and re-enable.

## Implementation Phases

### Phase 1: API Verification And Skeleton

- Inspect latest stable NodeBB source or local checkout.
- Confirm hooks for SSO login button/strategy registration.
- Confirm admin route helper signatures.
- Confirm settings API.
- Confirm user creation, email lookup, email confirmation, and custom field APIs.
- Add `package.json`, `plugin.json`, `library.js`, and empty admin page.
- Add lint/test scripts that can run outside a full NodeBB instance where possible.
- Record any explicit settings or debug levers discovered in this phase and plan ACP exposure immediately instead of leaving them implicit.

### Phase 2: Configuration And Admin UI

- Implement settings loader/saver.
- Implement secret-preserving save behavior.
- Implement callback URL display.
- Implement field validation.
- Implement OIDC discovery.
- Add admin tests or fixtures.
- Establish and follow the ongoing rule for later phases: when new runtime toggles are introduced, extend the ACP in the same change rather than deferring them.

### Phase 3: OIDC Flow

- Implement login redirect.
- Implement callback state validation.
- Implement code exchange.
- Implement ID token/userinfo validation.
- Normalize claims.
- Add protocol-level failure logging.

### Phase 4: Identity Resolution

- Implement sub lookup.
- Implement verified-email linking.
- Implement user creation.
- Implement mapping writes.
- Implement conflict handling.
- Implement email confirmation behavior.
- Add unit tests for all required identity cases.

### Phase 5: NodeBB Integration

- Wire successful login into NodeBB's auth/session flow.
- Add login/register button metadata.
- Confirm local login remains available.
- Verify admin page loads in ACP.
- Verify build output.

### Phase 6: Documentation And Release Readiness

- Expand README with install, activation, Authentik setup, and troubleshooting.
- Add `docs/SECURITY.md`.
- Add `docs/TEST_CHECKLIST.md`.
- Add `docs/NEXT_STEPS.md`.
- Add npm metadata and NodeBB compatibility declaration.
- Add changelog.
- Add dependency audit/update notes.

### Phase 7: Live-Test Hardening

- Add sanitized diagnostics for failed OIDC callbacks without logging raw tokens.
- Add optional provider authorization parameters such as `prompt=login` or `prompt=select_account`.
- Decide username-collision policy: safe unique username creation versus strict rejection.
- Add stale mapping repair/list tooling for `authentik:sub:uid`.
- Document Authentik enrollment policies for missing email, duplicate email, and duplicate username prevention.
- Verify actual emitted `email_verified` claims during live tests instead of assuming Authentik custom attributes affect OIDC output.

### Phase 8: Avatar Isolation And Profile Sync

- Investigate reports that new SSO-created users sometimes show an existing NodeBB user's avatar.
- Add diagnostics around account creation: resolved uid, created uid, provider `sub`, provider `picture`, and NodeBB avatar fields before and after writes.
- Confirm the plugin never copies profile fields from `req.uid`, the current browser session, or a previously linked account into a new SSO-created uid.
- Implement profile synchronization only after identity resolution succeeds.
- Add admin settings for per-field sync:
  - `syncEmail`
  - `syncUsername`
  - `syncFullname`
  - `syncAvatar`
  - explicit custom claim-to-user-field mappings
- Add a role/group attachment synchronization subsystem:
  - Configure mappings in ACP as table rows: NodeBB group, Authentik role/group identifier, sync direction, ownership/removal policy, priority, and enabled flag.
  - Support Authentik to NodeBB reads from OIDC claims such as `groups`, `roles`, or a configured custom claim.
  - Support NodeBB to Authentik writes only when an Authentik management API endpoint/token is configured; do not attempt remote role mutation through OIDC tokens.
  - Allow one-way mappings by default. Bidirectional mappings must be opt-in and should require explicit admin confirmation because they can create loops or privilege escalation.
  - Removal behavior must be configurable per mapping: add-only, remove when source membership disappears, or manual removal only.
  - Apply role sync only after identity resolution by `sub`; never use username or email as authority for group/role changes.
  - Run role sync as a separate post-login/scheduled sync step with dry-run support, not inside the identity-linking transaction.
  - Store audit metadata: `authentikLastRoleSyncedAt`, mapping version, last source snapshot hash, and per-mapping status/errors where practical.
  - Add an audit tool for drift: NodeBB group membership differs from mapped Authentik role/group state.
  - Add guardrails for privileged mappings: NodeBB admin/moderator groups and Authentik administrative roles require confirmation and should be disabled by default.
- Add conflict policies:
  - Email collision always fails closed.
  - Username collision can either reject, keep local username, or generate a unique username, depending on admin setting.
  - Avatar sync can skip invalid or missing `picture` claims without blocking login.
- Add role/group conflict policies:
  - If a role/group is mapped in both directions with different observed source state, use the configured owner or fail the mapping with an audit warning.
  - If Authentik API writes fail, keep login successful by default but record sync failure and leave local identity mapping untouched.
  - If a privileged mapping would grant more access than intended, fail closed and require admin review.
- Store sync metadata such as `authentikLastSyncedAt`, `authentikLastEmail`, `authentikLastUsername`, and `authentikLastPicture`.
- Add unit tests and live tests for email change, username change, username collision, missing `picture`, invalid avatar URL, valid avatar URL, local profile edits, custom field mappings, role/group add/remove behavior, bidirectional loop prevention, Authentik API failure, and privileged mapping confirmation.

### Phase 9: ACP Expansion And Operator UX

- Redesign the ACP page into grouped panels for provider connection, login behavior, identity rules, synchronization, and diagnostics/repair.
- Add settings for:
  - plugin enablement
  - display name
  - client id and secret
  - issuer and endpoints
  - scopes
  - PKCE
  - development HTTP callback allowance
  - custom authorization parameters
  - new-account creation policy
  - username collision policy
  - stale mapping cleanup policy
  - per-field synchronization toggles
  - role/group attachment mappings
  - diagnostics mode
- Add operator actions:
  - discover provider metadata
  - test JWKS
  - copy callback URL
  - show sanitized last failure
  - audit identity mappings
  - repair stale mappings
  - dry-run profile and role/group sync for a uid or `sub`
- Add frontend UX details:
  - inline field errors
  - loading states
  - disabled save while saving
  - confirmation dialogs for destructive or overwrite-heavy settings
  - clear secret-present indicator without exposing saved secret
  - warnings for development-only settings
- Add API endpoints and tests for settings validation, diagnostics, audit, repair, and dry-run sync.
- Keep the first ACP iteration conservative: no raw token/claim display and no destructive action without explicit confirmation.

### Phase 10: User Profile OIDC Controls

- Add a NodeBB profile/settings section for linked OIDC account state.
- Initially show only NodeBB-controlled and safely derived fields:
  - linked/unlinked status
  - provider display name
  - issuer
  - last login time
  - last sync time
  - last provider email seen
  - local fields managed by Authentik sync
- Add user actions:
  - refresh profile from Authentik by re-running OIDC login
  - disconnect Authentik only when admin policy allows it and a fallback login method exists
  - open configured Authentik self-service profile/password/MFA/session URLs
- Add ACP settings for external Authentik self-service URLs.
- Add read-only indicators to local profile fields managed by Authentik sync.
- Add permission and safety checks:
  - users cannot edit `authentikSub`, issuer, or mapping data
  - users cannot force-link a different Authentik subject over the current mapping
  - disconnect requires CSRF protection, confirmation, and fallback-login verification
  - refresh/sync resolves by linked `sub`, never username or user-provided email
- Add tests for panel rendering, permissions, external links, disconnect policy, and managed-field indicators.

### Phase 11: Authentik Session Closure And Single Logout

- Add an ACP toggle for OIDC back-channel logout.
- Display and copy the computed back-channel logout URL for Authentik provider configuration.
- Store validated OIDC `sid` from login claims when available, without exposing it in public user data.
- Add `POST /auth/authentik/backchannel-logout`.
- Validate the signed logout token with configured issuer, audience, JWKS, supported algorithms, required logout event, `iat`, `jti`, and no `nonce`.
- Resolve logout by permanent `sub` first, then stored `sid`.
- Revoke NodeBB sessions through `user.auth.revokeAllSessions(uid)`.
- Log ignored, unmatched, and rejected logout requests without logging raw tokens.
- Add automated tests for setting persistence, logout token validation, disabled behavior, `sub` mapping, and `sid` mapping.
- Live-test against Authentik by closing a session from the Authentik `auth` page and confirming the linked NodeBB session is cut off.

## Release Acceptance Criteria

- All identity unit tests pass.
- Admin settings save and reload correctly.
- Authentik login works against a real local/staging provider.
- Duplicate user creation by verified email is prevented.
- Unverified email cannot create or link an unlinked account.
- `sub` continues to resolve the same uid after email changes.
- Collision cases reject with warnings.
- Client secret is not exposed by settings read APIs.
- README documents setup and security model.
- Live tests confirm missing email rejection, stale mapping recovery, repeat login by `sub`, and existing-email linking.
- Unverified-email live tests inspect actual OIDC claims and confirm `email_verified === false` is rejected.
- New SSO-created users do not inherit avatar or profile fields from any existing NodeBB session/user.
- Profile synchronization is disabled by default or clearly documented, and each synced field has tests for conflicts and missing claims.
- ACP exposes useful toggles and diagnostics without exposing secrets or raw tokens.
- ACP repair and sync dry-run tools are covered by tests before destructive actions are enabled.
- User profile OIDC controls expose only safe link/sync state, with Authentik-managed actions handled through configured redirects or read-only indicators.

## Source References

- NodeBB plugin manifest and asset conventions: <https://docs.nodebb.org/development/plugins/plugin.json/>
- NodeBB plugin development and `require.main.require`: <https://docs.nodebb.org/development/plugins/>
- NodeBB plugin hooks and route lifecycle overview: <https://docs.nodebb.org/development/plugins/hooks/>
- NodeBB development/build/test workflow: <https://docs.nodebb.org/development/>
- Current NodeBB OAuth2 plugin used only as an API-pattern reference, not as a fork base: <https://github.com/NodeBB/nodebb-plugin-sso-oauth2-multiple>
