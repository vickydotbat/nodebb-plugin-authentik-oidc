# Security Notes

`nodebb-plugin-authentik-oidc` treats exact OIDC `issuer + sub` as the permanent external identity. Email is not a normal-login account-binding factor unless an administrator explicitly enables the trusted verified-email migration policy.

The plugin deliberately rejects logins when:

- `sub` is missing.
- `email` is missing.
- `email_verified` is missing, false, or a non-boolean value for an identity that is not already linked by `sub`.
- An existing `sub` mapping and verified email point to different NodeBB users.
- A verified email belongs to a NodeBB account already linked to another `sub`.
- ID token and userinfo `sub` values differ.
- A legacy `sub`-only mapping exists but the linked user's stored issuer does not exactly match the configured issuer.
- A subject mapping points to a missing/deleted NodeBB user.
- The resolved NodeBB user is currently restricted from login by NodeBB ban policy.
- The resolved NodeBB user has common disabled/suspended/deactivated account flags set.
- Trusted verified-email auto-linking targets a local account whose email is not already confirmed.
- Trusted verified-email auto-linking targets a local admin/moderator/privileged account.

The plugin never links or finds accounts by username. `preferred_username` and `name` are only used to seed the initial display username for newly created NodeBB users.

Admins can disable new SSO account creation. In that mode, an existing issuer-qualified subject mapping still logs in, but a verified email match alone does not link to an existing NodeBB user under the default policy.

The optional trusted verified-email auto-linking policy is only for deliberate migration windows. Even then, the target local account must already have a confirmed local email and must not be an admin/moderator/privileged account. Privileged accounts require explicit logged-in linking or administrator repair, not silent email-based migration.

Already-linked accounts continue to resolve by stored `sub` when the provider later emits an unverified email claim, as long as the email is present and does not collide with another NodeBB uid. The unverified email is not used to create or link an account.

Secrets, authorization codes, access tokens, refresh tokens, and raw ID tokens must not be logged. Admin settings responses show only a placeholder when a client secret is saved.

The ACP Last failure diagnostic stores only sanitized failure metadata: rejection code, stage, issuer metadata, claim presence flags, `email_verified` type/value, and whether userinfo contributed claims. It deliberately does not store raw tokens, authorization codes, full ID token/userinfo payloads, email addresses, or usernames.

The ACP Last authorization diagnostic stores sanitized authorization and clear-session preflight metadata, including whether the return target was provider-relative. This is intended for debugging Authentik flow rewrites such as `next=/` without storing state, nonce, PKCE verifier data, authorization codes, or tokens.

The user-facing linked-account page deliberately does not expose the OIDC `sub`, reverse mapping keys, raw claims, tokens, or authorization artifacts. It shows only linked status, provider display name, issuer, timestamps, the last provider email seen by the plugin, and configured external self-service links.

Display name synchronization, when enabled, runs only after identity resolution has succeeded by issuer-qualified `sub`. The provider `name` claim is not used for identity, missing names do not erase the local `fullname`, and obvious staff/system names such as `Admin`, `Moderator`, `System`, and `Root` are skipped for non-privileged users.

Admin-triggered provider discovery, JWKS diagnostics, provider endpoints, and self-service links are restricted to HTTPS URLs by default and reject localhost or private network targets. Callback HTTP and loopback provider HTTP have separate explicit development overrides. This reduces SSRF risk from ACP diagnostics and prevents unsafe links from being rendered to users.

PKCE is always enabled and generated with `openid-client` primitives. The plugin rejects `offline_access` scopes because refresh tokens are intentionally unsupported, confidential token exchange defaults to `client_secret_basic`, normal login ID-token validation is handled by `openid-client`, and back-channel logout token verification is handled by `jose`. Signing algorithms default to the Authentik-typical `RS256` unless an administrator explicitly pins another supported asymmetric algorithm.

Provider requests made through `openid-client` and `jose` use a custom fetch wrapper that validates the original provider URL, disables automatic redirects, validates redirect targets when present, and rejects provider redirects rather than following them. This keeps discovery, token, UserInfo, and JWKS requests inside the same SSRF safety model as the plugin's direct HTTP helper.

## Provider Boundary

The plugin can only enforce identity rules after Authentik redirects back with OIDC claims. It cannot stop Authentik from creating or verifying an Authentik-side account during an upstream enrollment flow. Authentik flows and policies should block provider-side registration when a username or email is already in use, when email is missing, or when the user has not completed the intended verification step.

For live testing, do not assume Authentik custom attributes change OIDC claims. A custom attribute such as `email_verified: false` must be verified by inspecting the actual ID token or userinfo response. For unlinked identities, the plugin rejects when the received `email_verified` claim is the boolean `false`, missing, or any non-boolean value.

## Hardening Backlog

- Expand diagnostics beyond the last failure record when needed, while keeping token and raw claim payload storage prohibited.
- Add tests or live verification for provider-specific prompts such as `prompt=login` or `prompt=select_account`.
- Evaluate whether the strict username-collision policy should become the recommended release default for this installation. This is a product/admin policy, not an identity-safety requirement.
- Add cleanup tooling for stale `authentik:sub:uid` mappings and duplicate test accounts created during early live testing.
- Keep Authentik-side flow/policy guidance current as Authentik changes its email-verification and logout behavior.

## Profile Synchronization Security

Authentik can be treated as the source of truth for profile data only after the NodeBB account has been resolved by `sub` or by verified-email linking. Synchronization must never happen based on username alone.

Synchronization rules should be explicit per field:

- Email updates require `email_verified === true` and must fail closed on collision with another NodeBB uid.
- Username updates are display/profile changes only. They must respect NodeBB username/userslug uniqueness and must not affect identity mapping.
- Avatar updates must only accept safe `https:` image URLs from trusted claims such as `picture`, with size, content-type, and timeout limits if the plugin downloads or proxies images.
- Custom field sync must use an allowlist of claim-to-field mappings. The plugin must not blindly copy all provider claims to NodeBB user fields.
- Local edits may be overwritten only for fields where synchronization is explicitly enabled by the admin.

Role/group attachment synchronization is higher risk than profile synchronization because it can grant access in both systems. It should be designed as an explicit mapping table, not automatic mirroring:

- Each mapping must name the NodeBB group and Authentik role/group identifier explicitly.
- Each mapping must declare its direction: Authentik to NodeBB, NodeBB to Authentik, or bidirectional.
- Each mapping must declare ownership and removal behavior: add-only, remove when source membership disappears, or manual removal only.
- NodeBB to Authentik writes require a dedicated Authentik management API token with the smallest practical scope. OIDC access tokens must not be treated as role-management authority unless the provider is deliberately configured for that and reviewed.
- Bidirectional mappings must prevent loops. A change applied from Authentik during one sync pass must not be echoed back as a NodeBB-originated change in the same pass, and vice versa.
- Privileged groups and roles require explicit admin confirmation and should be disabled by default. This includes NodeBB admin/moderator groups and Authentik administrative roles.
- Role sync failures should not alter identity mappings. By default they should allow login to complete, record an audit warning, and leave access unchanged unless an admin marks a mapping as login-critical.

The observed issue where newly-created Authentik users sometimes appeared with an existing NodeBB avatar is a P0 session/profile contamination risk until fully explained and fixed. It is not merely cosmetic: it can indicate that backend session state, account-selection UI, or profile synchronization is pointing the user at another profile. New SSO account creation must update profile fields only on the resolved uid. The only acceptable case for showing an existing NodeBB avatar during Authentik login/enrollment is verified-email linking to that exact existing NodeBB account after identity checks select that uid.

NodeBB-to-Authentik avatar synchronization is acceptable only as an explicit future source-of-truth mode. It must run after identity resolution by stored `sub` or verified-email link, use a least-privilege Authentik management API token, and write the selected NodeBB uid's avatar to the linked Authentik user. It must not use browser session state, displayed avatars, usernames, or unresolved enrollment context as authority.

Current live status: both OIDC end-session and Authentik invalidation-flow preflight attempts have still rendered enrollment with another user's avatar. The invalidation-flow attempt produced `next=/`, suggesting Authentik rewrote the intended return URL or did not execute the expected logout stage. Until this is resolved, session/profile contamination remains a release blocker.

## User-Facing OIDC Controls

NodeBB user profile controls may show OIDC link status and synchronization state, but they must not expose writable identity mapping internals. Users should not be able to edit `authentikSub`, issuer, reverse mapping keys, or claim-derived identity state directly.

Allowed user-facing controls should be limited to safe actions:

- Refresh profile data by re-running the OIDC flow for the currently linked account.
- Open configured Authentik self-service URLs for profile, password, MFA, or session management.
- Disconnect Authentik only when admin policy allows it and the account has a verified fallback login method.
- View which local profile fields are Authentik-managed.

Disconnect and refresh actions require CSRF protection and must resolve the linked account by stored `sub`. They must never accept a username, email, or arbitrary provider subject supplied by the browser as authority.

Current implementation status: the user-facing page is read-only and supports only configured external Authentik self-service links. Refresh and disconnect actions remain deferred until they can enforce the stored `sub` during the OIDC round trip.

## Session Revocation Boundary

Closing or revoking sessions from Authentik terminates NodeBB sessions only when OIDC back-channel logout is enabled in the plugin and configured on the Authentik provider. Revoking consent for the NodeBB provider is not a logout signal by itself; Authentik must terminate a user session and dispatch a back-channel logout request for the active OIDC provider session.

The back-channel logout handler:

- Is disabled by default and controlled by an ACP toggle.
- Accepts only signed OIDC logout tokens from the configured issuer/audience and JWKS.
- Requires the standard back-channel logout event, `iat`, `jti`, and either `sub` or `sid`.
- Rejects logout tokens with `nonce`.
- Maps issuer-qualified `sub` to the permanent Authentik subject mapping, or `sid` to the OIDC session id captured during login.
- Calls NodeBB's session-specific revocation API for a mapped `sid` when a NodeBB session id is available; subject-only logout falls back to revoking sessions for the mapped uid.
- Does not store access tokens, refresh tokens, raw ID tokens, or logout tokens.
- Records only sanitized ACP diagnostics for the last back-channel logout attempt: whether a request was seen, whether a logout token was present and validated, whether `sub`/`sid` were present, the matched uid, and the outcome.

Subject-only logout intentionally revokes sessions for the mapped uid because the provider did not identify a specific RP session. When `sid` and the NodeBB session id are available, logout is limited to that mapped session.

OIDC back-channel logout is intentionally not protected by a browser CSRF token because Authentik calls it server-to-server. It must remain POST-only and token-authenticated: no cookie-session mutation should be added to this route unless it is still gated by signed logout-token validation.

## NodeBB Deployment Requirements

Clustered NodeBB deployments must use a shared NodeBB session store so the login-start request and callback request can access the same session-backed OIDC state, nonce, and PKCE verifier. The plugin deliberately has no process-memory fallback for auth state.

Production NodeBB session cookies must be configured with HttpOnly, Secure behind HTTPS, and SameSite=Lax or another explicitly reviewed value. Cookie attributes and session regeneration are owned by NodeBB/Passport, so they must be verified in a running NodeBB 4.x deployment before release.

The plugin adds explicit CSRF middleware to admin mutation routes when the target NodeBB middleware exposes one, and the ACP client sends `x-csrf-token`. Route-level CSRF behavior should still be verified against the target NodeBB version.
