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

Secrets, authorization codes, access tokens, refresh tokens, and raw ID tokens must not be logged. Admin settings responses show only a placeholder when a client secret is saved.

The ACP Last failure diagnostic stores only sanitized failure metadata: rejection code, stage, issuer metadata, claim presence flags, `email_verified` type/value, and whether userinfo contributed claims. It deliberately does not store raw tokens, authorization codes, full ID token/userinfo payloads, email addresses, or usernames.

## Provider Boundary

The plugin can only enforce identity rules after Authentik redirects back with OIDC claims. It cannot stop Authentik from creating or verifying an Authentik-side account during an upstream enrollment flow. Authentik flows and policies should block provider-side registration when a username or email is already in use, when email is missing, or when the user has not completed the intended verification step.

For live testing, do not assume Authentik custom attributes change OIDC claims. A custom attribute such as `email_verified: false` must be verified by inspecting the actual ID token or userinfo response. The plugin rejects only when the received `email_verified` claim is the boolean `false`, missing, or any non-boolean value.

## Hardening Backlog

- Expand diagnostics beyond the last failure record when needed, while keeping token and raw claim payload storage prohibited.
- Add tests or live verification for provider-specific prompts such as `prompt=login` or `prompt=select_account`.
- Evaluate whether the strict username-collision policy should become the recommended release default for this installation. This is a product/admin policy, not an identity-safety requirement.
- Add cleanup tooling for stale `authentik:sub:uid` mappings and duplicate test accounts created during early live testing.
- Document Authentik flow policies for rejecting missing email and pre-existing username/email before provider-side account creation completes.

## Profile Synchronization Security

Authentik can be treated as the source of truth for profile data only after the NodeBB account has been resolved by `sub` or by verified-email linking. Synchronization must never happen based on username alone.

Synchronization rules should be explicit per field:

- Email updates require `email_verified === true` and must fail closed on collision with another NodeBB uid.
- Username updates are display/profile changes only. They must respect NodeBB username/userslug uniqueness and must not affect identity mapping.
- Avatar updates must only accept safe `https:` image URLs from trusted claims such as `picture`, with size, content-type, and timeout limits if the plugin downloads or proxies images.
- Custom field sync must use an allowlist of claim-to-field mappings. The plugin must not blindly copy all provider claims to NodeBB user fields.
- Local edits may be overwritten only for fields where synchronization is explicitly enabled by the admin.

The observed issue where newly-created Authentik users sometimes appeared with an existing NodeBB avatar should be treated as a profile-isolation bug until proven to be only Authentik/browser-session UI. New SSO account creation must update profile fields only on the resolved uid.

## User-Facing OIDC Controls

NodeBB user profile controls may show OIDC link status and synchronization state, but they must not expose writable identity mapping internals. Users should not be able to edit `authentikSub`, issuer, reverse mapping keys, or claim-derived identity state directly.

Allowed user-facing controls should be limited to safe actions:

- Refresh profile data by re-running the OIDC flow for the currently linked account.
- Open configured Authentik self-service URLs for profile, password, MFA, or session management.
- Disconnect Authentik only when admin policy allows it and the account has a verified fallback login method.
- View which local profile fields are Authentik-managed.

Disconnect and refresh actions require CSRF protection and must resolve the linked account by stored `sub`. They must never accept a username, email, or arbitrary provider subject supplied by the browser as authority.
