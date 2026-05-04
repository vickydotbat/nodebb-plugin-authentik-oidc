# Security Notes

`nodebb-plugin-authentik-oidc` treats the OIDC `sub` claim as the permanent external identity. Email is only a secondary linking mechanism and only when `email_verified` is the boolean `true`.

The plugin deliberately rejects logins when:

- `sub` is missing.
- `email` is missing.
- `email_verified` is missing, false, or a non-boolean value.
- An existing `sub` mapping and verified email point to different NodeBB users.
- A verified email belongs to a NodeBB account already linked to another `sub`.
- ID token and userinfo `sub` values differ.

The plugin never links or finds accounts by username. `preferred_username` and `name` are only used to seed the initial display username for newly created NodeBB users.

Admins can disable new SSO account creation. In that mode, an existing `sub` mapping still logs in and a verified email can still link to an existing NodeBB user, but an otherwise new verified OIDC identity is rejected without creating a user or mapping.

Secrets, authorization codes, access tokens, refresh tokens, and raw ID tokens must not be logged. Admin settings responses show only a placeholder when a client secret is saved.

The ACP Last failure diagnostic stores only sanitized failure metadata: rejection code, stage, issuer metadata, claim presence flags, `email_verified` type/value, and whether userinfo contributed claims. It deliberately does not store raw tokens, authorization codes, full ID token/userinfo payloads, email addresses, or usernames.

The user-facing linked-account page deliberately does not expose the OIDC `sub`, reverse mapping keys, raw claims, tokens, or authorization artifacts. It shows only linked status, provider display name, issuer, timestamps, the last provider email seen by the plugin, and configured external self-service links.

Display name synchronization, when enabled, runs only after identity resolution has succeeded by `sub` or verified email. The provider `name` claim is not used for identity and missing names do not erase the local `fullname`.

Admin-triggered provider discovery, JWKS diagnostics, provider endpoints, and self-service links are restricted to HTTPS URLs by default and reject localhost or private network targets. Loopback HTTP is allowed only when the explicit development override is enabled. This reduces SSRF risk from ACP diagnostics and prevents unsafe links from being rendered to users.

## Provider Boundary

The plugin can only enforce identity rules after Authentik redirects back with OIDC claims. It cannot stop Authentik from creating or verifying an Authentik-side account during an upstream enrollment flow. Authentik flows and policies should block provider-side registration when a username or email is already in use, when email is missing, or when the user has not completed the intended verification step.

For live testing, do not assume Authentik custom attributes change OIDC claims. A custom attribute such as `email_verified: false` must be verified by inspecting the actual ID token or userinfo response. The plugin rejects only when the received `email_verified` claim is the boolean `false`, missing, or any non-boolean value.

## Hardening Backlog

- Expand diagnostics beyond the last failure record when needed, while keeping token and raw claim payload storage prohibited.
- Add tests or live verification for provider-specific prompts such as `prompt=login` or `prompt=select_account`.
- Evaluate whether the strict username-collision policy should become the recommended release default for this installation. This is a product/admin policy, not an identity-safety requirement.
- Add cleanup tooling for stale `authentik:sub:uid` mappings and duplicate test accounts created during early live testing.
- Document Authentik flow policies for rejecting missing email and pre-existing username/email before provider-side account creation completes.
- Consider DNS resolution checks for discovery/JWKS requests if the deployment allows arbitrary hostnames that can resolve to private addresses.

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

The observed issue where newly-created Authentik users sometimes appeared with an existing NodeBB avatar should be treated as a profile-isolation bug until proven to be only Authentik/browser-session UI. New SSO account creation must update profile fields only on the resolved uid.

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

Closing or revoking sessions from Authentik's `auth` page terminates NodeBB sessions only when OIDC back-channel logout is enabled in the plugin and configured on the Authentik provider.

The back-channel logout handler:

- Is disabled by default and controlled by an ACP toggle.
- Accepts only signed OIDC logout tokens from the configured issuer/audience and JWKS.
- Requires the standard back-channel logout event, `iat`, `jti`, and either `sub` or `sid`.
- Rejects logout tokens with `nonce`.
- Maps `sub` to the permanent Authentik subject mapping, or `sid` to the OIDC session id captured during login.
- Calls NodeBB's session revocation API for the mapped uid.
- Does not store access tokens, refresh tokens, raw ID tokens, or logout tokens.

This intentionally revokes all NodeBB sessions for the mapped uid rather than trying to keep a local browser-session-to-OIDC-session graph. That is conservative for the current plugin goal: an upstream Authentik session closure should not leave an active NodeBB session behind.
