Use this as the coding-agent prompt:

```text
Build a modern NodeBB plugin that adds generic Authentik-compatible OAuth2/OIDC login for current NodeBB versions.

Project name:
nodebb-plugin-authentik-oidc

Goal:
Create a maintained, minimal, secure NodeBB SSO plugin for Authentik and other standards-compliant OIDC providers.

Problem:
Existing NodeBB OAuth/OIDC plugins are not sufficient:
- nodebb-plugin-sso-oauth2-multiple: generic OAuth2, weak/unclear existing-user linking, observed duplicate account creation when email already existed.
- nodebb-plugin-sso-oidc: stale, broken admin settings save flow, outdated claim assumptions such as user_name instead of preferred_username, fragile code.
- fusionauth-oidc-style plugins: dependency/build rot and not clearly compatible with latest NodeBB.
- Old generic OAuth2 repositories appear deprecated, missing, or unmaintained.

Primary requirement:
Reliable identity linking. The plugin must never create duplicate NodeBB users when a verified email already belongs to an existing account.

Target:
- Latest stable NodeBB
- Authentik as the main tested provider
- Generic OIDC compatibility where reasonable

Core identity rules:
1. OIDC `sub` is the permanent external identity.
2. Email is only a secondary linking mechanism.
3. Link by email only when `email_verified === true`.
4. Never use username as identity.
5. `preferred_username` is only for display/initial username.
6. Once linked, repeat login must resolve by `sub`, even if email later changes.
7. If `sub` maps to one uid but email maps to another uid, fail safely and log a security warning.
8. If email is missing, reject login.
9. If email is unverified and no existing `sub` mapping exists, reject login.

Required OIDC claims:
- sub
- email
- email_verified
- preferred_username optional
- name optional

Plugin behavior:
1. Add login route:
   /auth/authentik
2. Add callback route:
   /auth/authentik/callback
3. Redirect user to provider authorization endpoint.
4. Exchange authorization code for tokens.
5. Retrieve or parse userinfo/id token claims.
6. Resolve NodeBB user:
   a. Existing sub mapping → login mapped uid.
   b. No sub mapping + verified email matches existing NodeBB user → link sub to existing uid, then login.
   c. No match + verified email → create new NodeBB user, then link sub.
   d. Missing/unverified email → fail safely.
7. Store mapping in NodeBB DB:
   authentik:sub:<sub> -> uid
   user:<uid>.authentikSub = <sub>
   user:<uid>.authentikLinkedAt = timestamp
8. Mark email confirmed only when `email_verified === true`.

Admin UI requirements:
- Settings page must work on current NodeBB.
- Settings must load and save correctly.
- Required fields:
  - clientId
  - clientSecret
  - issuer
  - authorizationEndpoint
  - tokenEndpoint
  - userinfoEndpoint
  - scopes, default: openid email profile
  - callback URL display/copy field
- Support OIDC discovery from issuer if practical.
- Do not expose saved client secret unnecessarily.
- Include clear validation errors.

Security requirements:
- Validate state.
- Validate issuer.
- Validate required claims.
- Use HTTPS callback URLs.
- Do not silently create accounts on claim conflict.
- Do not allow username-based account takeover.
- Keep local NodeBB login available unless explicitly disabled by admin setting.
- Log rejected login reasons without leaking secrets.

Logging:
Info:
- login by existing sub
- linked existing user by verified email
- created new user
Warn:
- missing email
- unverified email
- sub/email collision
- unexpected provider response
Error:
- token exchange failure
- userinfo failure
- database write failure

Testing plan:
Create tests or at least documented test fixtures for:
1. New verified OIDC user creates one NodeBB user.
2. Same `sub` logs into same uid repeatedly.
3. Existing NodeBB user with same verified email links with no duplicate.
4. Same email but `email_verified=false` does not link/create.
5. Username conflict with different email creates safe unique username.
6. Existing `sub` with changed email still resolves by sub.
7. `sub` mapped to uid A but email belongs to uid B fails safely.
8. Missing email fails safely.
9. Admin settings save and reload correctly.

Planning outline:
Phase 1:
- Inspect current NodeBB plugin API for auth strategy registration, admin settings, user creation, and DB access.
- Identify current conventions for login route registration and admin UI.
- Decide whether to use passport-openidconnect, openid-client, or direct OAuth/OIDC implementation.
- Prefer a small dependency surface.

Phase 2:
- Build minimal working login flow.
- Hardcode local test config first if needed.
- Confirm login route and callback work.

Phase 3:
- Implement identity resolution and safe linking logic.
- Add database mapping.
- Add conflict handling.

Phase 4:
- Build admin settings page.
- Add validation and OIDC discovery.

Phase 5:
- Add tests, logging, README, migration notes, and operational checklist.

Deliverables:
- Working NodeBB plugin source.
- README with Authentik setup instructions.
- Security notes explaining identity rules.
- Test checklist.
- Clear install/activate/build instructions.

Do not:
- Fork stale plugins unless only borrowing small ideas.
- Depend on username matching.
- Assume email is verified unless the provider explicitly says so.
- Hide errors behind silent account creation.
- Require manual MongoDB edits for normal operation.
```
