Medium: provider-session clearing can be bypassed with a user-controlled query flag

Affected: lib/strategy.js (line 39)

Exploit scenario: If clearProviderSessionBeforeLogin is enabled, an attacker can send a victim to /auth/authentik?authentikFreshLogin=1. The strategy treats that query parameter as proof that the provider session was already cleared and skips the clearing redirect.

Why unsafe: authentikFreshLogin is a public, unauthenticated GET parameter. It should not control a security-sensitive login-flow branch.

Exact fix: Replace req.query.authentikFreshLogin with a one-time server-side session marker created immediately before redirecting to the provider logout/session-clear endpoint. Consume that marker before allowing the bypass.

Regression test: In test/strategy.test.js, configure clearProviderSessionBeforeLogin: true, call initial auth with query: { authentikFreshLogin: '1' } and no session marker, and assert the strategy still redirects to the configured session-clear endpoint.



Medium: PKCE can be disabled by configuration

Affected: lib/config.js (line 32), lib/state.js (line 25), lib/oidc.js (line 323)

Exploit scenario: If an admin disables PKCE, an intercepted or injected authorization code has one less binding to the browser/session that initiated login. Confidential client authentication helps, but RFC 9700’s direction is to use PKCE for authorization-code clients.

Why unsafe: This weakens code-injection/interception defenses and leaves the plugin below current OAuth2 BCP expectations.

Exact fix: Remove the usePkce setting, always generate a verifier, always send code_challenge_method=S256, and always include code_verifier in the token request. If a legacy escape hatch is kept, make it hidden/explicitly documented and refuse it by default.

Regression test: Add config/state/OIDC tests asserting saved settings cannot disable PKCE and authorization URLs always include code_challenge plus code_challenge_method=S256.



Medium: ID-token validation does not explicitly require all OIDC-required freshness claims

Affected: lib/oidc.js (line 124)

Exploit scenario: A malformed or non-compliant signed ID token without exp, iat, or a usable sub can pass the generic JWT verification layer if the library does not require those claims. Also, when max_age=0 is sent for fresh login, the client does not require/check auth_time.

Why unsafe: OIDC Core requires ID-token claim validation beyond signature, issuer, audience, and nonce. Fresh-login enforcement is only meaningful if the returned token proves authentication time.

Exact fix: After jwt.verify, explicitly require sub as non-empty string, exp and iat as numbers, reject unreasonable token age, and when forceProviderLogin/max_age is used require numeric auth_time within the accepted freshness window.

Regression test: Add test/oidc.test.js cases rejecting ID tokens missing exp, missing iat, missing/empty sub, and missing/stale auth_time when fresh login is requested.



Low: confidential-client authentication only uses client_secret_post

Affected: lib/oidc.js (line 96)

Exploit scenario: Client secrets are sent in the form body. Body parameters are more likely to be captured by reverse-proxy/request-body logging than an Authorization header, and some providers only allow client_secret_basic.

Why unsafe: OAuth historically permits body credentials but does not prefer them. For confidential clients, supporting the provider’s advertised token endpoint auth method is safer and more interoperable.

Exact fix: Add tokenEndpointAuthMethod, default to client_secret_basic when a secret is configured, send Authorization: Basic base64(client_id:client_secret), and only use client_secret_post when explicitly configured/discovered.

Regression test: Add exchangeCode tests asserting Basic auth by default, no client_secret in the body for Basic mode, and explicit client_secret_post still works when configured.

----

OIDC callback endpoint audit - 2026-05-09

Confirmed controls:

- Authorization code exchange is server-to-server only. lib/strategy.js passes req.query.code to oidc.exchangeCode, and lib/oidc.js posts it directly to the configured token endpoint.
- The authorization code is not logged by plugin code and is not exposed to frontend JavaScript.
- Provider error callbacks are handled before token exchange or user resolution. The strategy records sanitized diagnostics and calls fail/error instead of success.
- Callback state is verified through stateStore.consume and deleted before token exchange, so wrong and replayed state values are rejected.
- Token endpoint configuration is validated by config.saveSettings: tokenEndpoint must be HTTPS unless the explicit local-development HTTP override is enabled.
- Outbound token requests use requestJson, which applies a 10 second timeout by default.

Medium: callback without code starts a new authorization flow instead of failing closed

Affected: lib/strategy.js (line 36)

Exploit scenario: A request to /auth/authentik/callback with only state, with no code, or with an IdP callback missing code because of a provider/proxy bug can be treated as a fresh login-start request. The strategy creates new state and redirects to Authentik instead of rejecting the malformed callback.

Why unsafe: Login-start and callback are different protocol stages. A callback endpoint should fail closed when code is missing, except for a standards-compliant error response from the IdP. Redirecting from a malformed callback can hide provider errors, complicate incident response, and create ambiguous state-machine behavior.

Exact fix: Distinguish callback route invocations from login-start invocations. If the request path is the callback URL path or NodeBB passes a callback marker, require exactly one code and exactly one state unless error is present. Missing code on the callback route should call fail/error and must not create new state or redirect to authorization.

Regression test: In test/strategy.test.js, invoke authenticate with a callback-path request and query { state: 'existing-state' } but no code. Assert state.create is not called, redirect is not called, exchangeCode is not called, and the strategy fails/errors.

Medium: callback accepts multiple code parameters

Affected: lib/strategy.js (line 74), lib/oidc.js (line 94)

Exploit scenario: An attacker or buggy proxy sends /auth/authentik/callback?code=attacker&code=victim&state=valid. Express-style query parsing can represent duplicate parameters as an array. The current truthiness check accepts the value and URLSearchParams coerces it when setting the token request body.

Why unsafe: OAuth callback parameters should be single valued. Accepting duplicate code or state parameters creates parser ambiguity between the application, framework, logs, and provider, and can lead to code substitution or hard-to-debug callback behavior.

Exact fix: Add a helper that requires req.query.code and req.query.state to be strings, not arrays, and non-empty after trim. Reject arrays or duplicate parameter representations before state consumption or token exchange.

Regression test: In test/strategy.test.js, call authenticate with query { code: ['a', 'b'], state: 'valid-state' }. Assert state.consume and exchangeCode are not called and the strategy fails/errors. Add the same test for duplicate state.

Low: callback route method handling is delegated to NodeBB and not asserted by plugin tests

Affected: library.js (lines 121-138)

Exploit scenario: If NodeBB's strategy route registration accepts POST or another unexpected method for /auth/authentik/callback, a callback could be delivered through an untested method and interact differently with body parsing, CSRF middleware, logs, caches, or proxy rules.

Why unsafe: OIDC authorization responses for response_mode=query are expected on GET. Unsupported HTTP methods should not accidentally enter the same callback state machine.

Exact fix: Confirm NodeBB's SSO strategy registration only mounts GET for callbackURL, or add plugin-owned route/middleware guards that reject non-GET callback requests with 405 before strategy execution.

Regression test: Add a routing/integration test for POST /auth/authentik/callback that asserts it is rejected and does not call state.consume or exchangeCode.

Low: token endpoint HTTPS is enforced at settings-save time but not rechecked at exchange time

Affected: lib/config.js (lines 165-168), lib/oidc.js (line 103), lib/http.js (line 141)

Exploit scenario: If settings are corrupted directly in the database, imported from an unsafe backup, or mutated by another plugin after validation, exchangeCode will pass an http:// tokenEndpoint to requestJson. requestJson allows both HTTP and HTTPS generically because it is shared by local-development and other request paths.

Why unsafe: Authorization codes, client credentials, and PKCE verifiers must only be sent to a TLS-protected token endpoint outside explicit local development. Relying only on settings-save validation leaves a defense-in-depth gap.

Exact fix: Before exchangeCode posts the token request, assert settings.tokenEndpoint is HTTPS unless allowInsecureCallbackUrlForDevelopment is enabled and the endpoint is loopback. Alternatively expose a config.assertSafeProviderUrl helper and call it from exchangeCode.

Regression test: Unit test exchangeCode with tokenEndpoint: 'http://auth.example.com/token' and allowInsecureCallbackUrlForDevelopment false. Assert requestJson is not called and the exchange rejects.

----

OIDC discovery and issuer validation audit - 2026-05-09

Confirmed controls:

- Discovery is exposed through the admin API only. library.js registers /authentik-oidc/discover behind middleware.ensureLoggedIn and ensureSettingsAdmin.
- The discovery issuer URL is admin-supplied and pre-validated with config.assertSafeUrl before fetching metadata.
- config.assertSafeUrl requires HTTPS by default and rejects localhost/private-network literal hosts unless the explicit local-development HTTP override is enabled.
- requestJson performs SSRF defense-in-depth for outbound discovery/JWKS/userinfo/token requests: it rejects localhost/private literal hosts, resolves DNS before the request, rejects private resolved addresses, and validates addresses again in the request lookup callback.
- ID token validation passes issuer: settings.issuer to jwt.verify, so the ID token iss must match the configured issuer according to the JWT library issuer check. No startsWith/includes/regex/hostname-only issuer matching was found in ID-token validation.
- Saved provider endpoints are validated in config.saveSettings: issuer, authorizationEndpoint, tokenEndpoint, userinfoEndpoint, and jwksUri must be HTTPS unless explicit local development HTTP is enabled.

Medium: discovery issuer comparison allows trailing-slash normalization instead of exact string match

Affected: lib/discovery.js (lines 5-10)

Exploit scenario: An administrator enters issuer https://auth.example.com/application/o/nodebb and discovery returns issuer https://auth.example.com/application/o/nodebb/. The plugin accepts the mismatch because issuersMatch trims trailing slashes before comparing.

Why unsafe: OIDC issuer identifiers are exact strings. Accepting normalized variants weakens issuer-mix-up defenses and violates the stricter audit requirement that discovered issuer exactly match the expected issuer. Even small normalization rules create precedent for future loose matching.

Exact fix: Change issuersMatch to return configuredIssuer === discoveredIssuer with no trimming. If Authentik operationally requires a trailing slash, normalize only at input-save time before discovery and token validation, and document that the stored configured issuer is the exact discovered issuer.

Regression test: Update test/discovery.test.js so discovery.discover('https://auth.example.com/application/o/nodebb') rejects metadata issuer 'https://auth.example.com/application/o/nodebb/'. Add a positive test where both strings are exactly equal.

Medium: discovered endpoint URLs are returned before endpoint-level HTTPS/private-network validation

Affected: lib/discovery.js (lines 25-31), lib/admin.js (lines 45-47)

Exploit scenario: A compromised or misconfigured discovery document at an otherwise allowed issuer returns authorization_endpoint, token_endpoint, or jwks_uri using http://, localhost, or a private-network host. The admin discover API returns those endpoints to the ACP response. Later config.saveSettings should reject unsafe endpoints before enabling the plugin, but discovery itself does not fail closed on unsafe metadata.

Why unsafe: Discovery metadata is security-critical configuration. Authorization, token, and JWKS endpoints should be validated immediately when fetched so administrators cannot accidentally trust or copy unsafe metadata, and so tests prove discovery output is safe before it reaches the UI.

Exact fix: In discovery.discover, validate authorization_endpoint, token_endpoint, and jwks_uri with the same HTTPS and private-network rules used by config.validate. Treat userinfo_endpoint and end_session_endpoint similarly when present. Pass the explicit local-development override into discovery validation if needed.

Regression test: Add discovery tests where metadata contains token_endpoint: 'http://auth.example.com/token', jwks_uri: 'https://127.0.0.1/jwks', or missing required endpoints. Assert discovery rejects before returning metadata.

Low: discovery fetch is based on admin POST body rather than persisted issuer setting

Affected: lib/admin.js (lines 35-45)

Exploit scenario: Any account with admin:settings privilege can POST an arbitrary safe-looking public issuer URL to /api/admin/plugins/authentik-oidc/discover and cause the server to fetch its discovery document, even if that issuer is not saved in plugin settings.

Why unsafe: This is admin-only and SSRF protections exist, so the practical risk is low. Still, fetching from transient request body broadens the server-side fetch surface compared with fetching only from already-saved provider configuration.

Exact fix: Prefer a two-step flow where the issuer is saved/validated first, then discovery fetches only the saved issuer. If keeping ad hoc discovery, preserve the current admin-only and SSRF controls and add audit tests documenting that non-admin users cannot call it.

Regression test: Add API route tests asserting unauthenticated users and users without admin:settings cannot call discover, and that discover uses the same safe URL validation as saveSettings.

----

ID token validation audit - 2026-05-09

Confirmed controls:

- ID tokens are required for login. lib/strategy.js rejects token responses that omit id_token before identity resolution.
- Signature validation uses JWKS. lib/oidc.js decodes the token header, selects a public key from the configured jwksUri, converts the JWK to a KeyObject, and calls jwt.verify.
- alg=none and symmetric algorithms are rejected before key selection because SUPPORTED_SIGNING_ALGORITHMS only includes RS256, RS384, RS512, ES256, ES384, and ES512.
- JWKs with unsupported kty values, encryption-only use, or unsupported alg values are ignored.
- jwt.verify is called with an asymmetric algorithm allowlist, audience: settings.clientId, and issuer: settings.issuer.
- The nonce from the ID token must match the nonce stored in the consumed login state.
- azp is validated. If present, it must equal client_id. If aud is an array with more than one audience, azp must be present.
- at_hash and c_hash are validated when present.

Medium: ID token validation does not explicitly require exp, iat, and sub claims

Affected: lib/oidc.js (lines 124-136)

Exploit scenario: A malformed signed token from the configured issuer that omits exp or iat could be accepted if jsonwebtoken does not reject the absence of those claims. A token with missing or empty sub can also pass verifyIdToken and fail later during identity resolution rather than at the protocol boundary.

Why unsafe: OIDC Core requires ID tokens to contain iss, sub, aud, exp, and iat. Relying on generic JWT verification without explicitly requiring these claims leaves protocol validation incomplete and makes failures happen later in account-linking logic.

Exact fix: After jwt.verify, explicitly require sub to be a non-empty string and exp and iat to be finite numeric values. Reject tokens missing any required ID-token claim before userinfo or identity resolution.

Regression test: Add test/oidc.test.js cases rejecting verified tokens missing exp, missing iat, missing sub, and empty sub.

Medium: ID token iat is not bounded for reasonable age or future skew

Affected: lib/oidc.js (lines 124-136)

Exploit scenario: A validly signed token with a very old iat but a long exp, or a token with an iat far in the future, can pass current validation if the JWT library accepts it. This weakens replay/freshness assumptions, especially when the plugin asks Authentik for prompt=login and max_age=0.

Why unsafe: exp prevents use after expiration, but iat should still be checked for sane issuance time. OIDC clients commonly reject tokens with implausible issued-at values and require auth_time when max_age is requested.

Exact fix: Add an ID token max age policy, for example reject iat older than a short configurable window or newer than now plus clock skew. When forceProviderLogin/max_age is used, require auth_time and validate it against the requested max_age plus clock skew.

Regression test: Add tests rejecting iat far in the future and iat older than the configured ID token max age. Add tests rejecting missing/stale auth_time when max_age=0 is sent.

Low: accepted ID token algorithms are broad and not provider-configurable

Affected: lib/oidc.js (lines 8-9, 124-128)

Exploit scenario: The plugin accepts any supported RSA or EC algorithm in its static allowlist. If the Authentik application is expected to use only RS256 or ES256, a token signed with another allowed algorithm such as RS512 or ES512 would still pass if a matching key is published in JWKS.

Why unsafe: A static broad allowlist is much safer than accepting alg from the token, but best practice is to pin the expected provider signing algorithm or derive it from trusted discovery/admin configuration. Narrowing algorithms reduces confusion during key rotation and limits acceptance of unexpected provider behavior.

Exact fix: Add an idTokenSigningAlg setting populated from trusted discovery or explicit admin config. Default to RS256 for Authentik unless discovery/config says otherwise. Use that setting both when filtering JWKs and in jwt.verify algorithms.

Regression test: Configure expected alg RS256, provide a token header alg ES256 with a valid EC key, and assert verification rejects it. Add a positive RS256 case.

Low: unknown-kid, wrong issuer, wrong audience, expired-token, unsigned-token, and wrong-nonce regression tests are incomplete or indirect

Affected: test/oidc.test.js (around lines 312-448)

Exploit scenario: A future refactor could weaken jwt.verify options, nonce checking, or key selection without the suite catching all checklist regressions because many tests mock jsonwebtoken.verify and do not exercise real JWT validation behavior for issuer, audience, expiration, nbf, or signature.

Why unsafe: ID-token validation is a primary account-takeover boundary. Tests should prove real library behavior for the critical rejection cases, not only check wrapper logic with mocked claims.

Exact fix: Add integration-style unit tests that generate real RSA/EC keypairs and real JWTs signed with jsonwebtoken. Exercise verifyIdToken end-to-end with a mocked JWKS fetch, not a mocked jwt.verify.

Regression tests to add:

- unsigned token or alg=none is rejected.
- token with wrong issuer is rejected.
- token with wrong audience is rejected.
- expired token is rejected.
- token with nbf in the future is rejected.
- token signed by unknown kid is rejected.
- token with changed alg is rejected.
- token from a different Authentik application/client is rejected by aud and/or azp.
- token with wrong nonce is rejected.

----

Access token, UserInfo, and identity-source audit - 2026-05-09

Confirmed controls:

- Canonical OIDC identity is based on sub once linked. identity.resolve first checks the stored sub mapping and returns the mapped uid before considering email.
- Email is not accepted without sub. identity.validateClaims rejects missing sub before any email lookup or account creation.
- Email is required and email_verified must be boolean true before first-time verified-email linking or new account creation.
- Missing email fails closed for unlinked identities.
- A provider email change for an already-linked sub still resolves by sub. If the new email belongs to another local uid, login fails closed with a sub/email collision.
- If two local users share the same email, verified-email linking fails closed.
- If two Authentik subjects attempt to link to the same local email, linkSub rejects an existing different authentikSub and tests cover concurrent verified-email links.
- UserInfo is called server-to-server with Authorization: Bearer access_token. The access token is not sent to frontend JavaScript by plugin code.
- UserInfo uses requestJson, which applies timeout, body-size, redirect, DNS, and private-address protections.
- UserInfo sub must match the ID token sub. Conflicting email or email_verified claims between ID token and UserInfo are rejected.
- UserInfo failure aborts login before identity resolution because getUserinfo is awaited before mergeClaims/identity.resolve.

High: external identity mapping key omits issuer

Affected: lib/identity.js (lines 9, 28, 54-63, 187-193)

Exploit scenario: An administrator changes the configured Authentik issuer, or a staging/production issuer mix-up occurs, and the new issuer emits the same sub value as an existing linked user. Because the lookup key is authentik:sub:uid keyed only by sub, the login can resolve to the existing NodeBB uid even though the subject belongs to a different issuer.

Why unsafe: OIDC sub is only unique within an issuer. The preferred stable external identity key is issuer + sub. Storing issuer as a user field is useful metadata, but it is not part of getUidBySub lookup, so it does not prevent cross-issuer subject collision.

Exact fix: Change the primary mapping key to include issuer, for example authentik:issuer-sub:uid mapping `${issuer}\x1f${sub}` to uid, and/or a direct key derived from a hash of issuer + sub. On login, look up by issuer + sub only. During migration, read legacy sub-only mappings only when authentikIssuer on the mapped user exactly matches the current issuer, then rewrite to the new composite key.

Regression test: Create a user linked with issuer A and sub shared-sub. Then resolve claims for issuer B with the same sub and a different verified email. Assert login does not return the issuer A uid and fails or creates/links according to policy using only issuer B + sub.

Medium: verified-email linking can attach a new Authentik subject to an existing local account

Affected: lib/identity.js (lines 297-309)

Exploit scenario: A local NodeBB account exists with email victim@example.com but has no Authentik subject linked yet. A newly authenticated Authentik subject with email victim@example.com and email_verified true logs in. The plugin links that Authentik sub to the existing NodeBB account.

Why unsafe: This can be intentional account continuity, but it makes verified email a first-link account binding factor. That is only safe if Authentik is the authoritative email verifier, prevents duplicate verified emails, and the local NodeBB email database is trusted and current. If local emails are stale, user-editable, or previously unverified in meaningful ways, this can become account takeover.

Exact fix: Keep verified-email linking disabled by default or make it an explicit admin policy with clear warnings. Safer default: create a new account for new sub values, or require the existing NodeBB user to be logged in and perform a CSRF-protected account-link flow. If automatic linking remains enabled, require email_verified === true, local email confirmed, no existing authentikSub, and no duplicate email matches.

Regression test: Add policy tests for allowVerifiedEmailAutoLink false: existing local email plus new verified Authentik sub must not link automatically. Add positive tests only when the policy is explicitly enabled and the local email is confirmed.

Medium: UserInfo can override non-conflicting ID-token profile claims wholesale

Affected: lib/oidc.js (lines 232-251)

Exploit scenario: ID token contains preferred_username or name from the signed token, while UserInfo returns different preferred_username or name. mergeClaims spreads UserInfo over ID-token claims after checking only sub, email, and email_verified. The resulting username seed/profile sync data comes from UserInfo.

Why unsafe: UserInfo is fetched over TLS and sub-matched, so this is not the same as trusting browser input. However, the signed ID token is the stronger authentication artifact. UserInfo should not silently override authentication-relevant assumptions, and profile fields should have clear precedence rules.

Exact fix: Treat ID token sub, iss, aud, nonce, and any auth/session claims as canonical. For profile claims, define explicit precedence: either prefer ID-token claims, prefer UserInfo only for documented profile fields, or reject conflicts for selected fields. Keep UserInfo unable to override issuer/client/session assumptions.

Regression test: Add mergeClaims tests where ID token and UserInfo have different preferred_username/name. Assert the configured precedence or conflict behavior.

Low: UserInfo endpoint TLS safety relies on settings validation and generic requestJson, not a UserInfo-specific preflight

Affected: lib/config.js (lines 165-169), lib/oidc.js (lines 221-229), lib/http.js (lines 139-153)

Exploit scenario: If settings are corrupted directly in the database after validation, getUserinfo will call requestJson with the stored userinfoEndpoint. requestJson allows http URLs generically, though it blocks private hosts and saveSettings normally rejects non-HTTPS endpoints.

Why unsafe: Access tokens should only be sent to the configured HTTPS UserInfo endpoint. Defense in depth should reassert endpoint safety immediately before sending bearer tokens.

Exact fix: Before getUserinfo sends Authorization: Bearer, assert userinfoEndpoint is HTTPS unless explicit loopback development mode is enabled. Prefer a provider-endpoint validator shared with token/JWKS requests.

Regression test: Unit test getUserinfo with userinfoEndpoint: 'http://auth.example.com/userinfo' and development override false. Assert requestJson is not called and the call rejects before sending the bearer token.

----

Account linking and takeover-prevention audit - 2026-05-09

Confirmed controls:

- email_verified is respected for unlinked identities. identity.resolve rejects first-time linking and account creation unless email_verified is exactly boolean true.
- Missing email rejects for unlinked identities.
- Two local NodeBB users with the same email cause verified-email linking to fail closed.
- Existing linked sub wins over email continuity, and a linked sub whose current email belongs to another uid fails closed.
- Existing local account with a different authentikSub cannot be relinked to a new sub.
- Username collisions are handled safely: the default policy generates a unique username suffix, and a reject policy is available.
- New SSO-created users have profile/avatar/signature-style fields cleared after creation to avoid inheriting current-session or existing-account visuals.
- Fullname sync is opt-in and does not blank the local fullname when the provider omits name.
- Stale sub mappings pointing to missing users are deleted before resolving by verified email.

High: automatic verified-email linking can take over existing local accounts, including privileged accounts

Affected: lib/identity.js (lines 302-309)

Exploit scenario: A local NodeBB admin account has email admin@example.com and no authentikSub. A new Authentik user authenticates with email admin@example.com and email_verified true. The plugin finds emailUid and links the new Authentik sub to that existing NodeBB account, returning the admin uid.

Why unsafe: Existing-account linking is an account takeover boundary. It requires proof that the browser controls the existing NodeBB account, or an explicit operator policy that Authentik verified email is authoritative for local-account ownership. The current default allows silent first-link takeover of any unlinked local account whose email matches.

Exact fix: Change the safe default so first login creates a new NodeBB account linked to issuer + sub. Existing account linking should require an explicit logged-in NodeBB account-link flow with CSRF protection, or an admin-enabled trusted-IdP-email-linking policy that clearly documents the risk. If automatic linking is enabled, block or require extra confirmation for privileged groups/admin accounts.

Regression test: Existing local NodeBB admin with email admin@example.com and no authentikSub; new OIDC subject with email admin@example.com and email_verified true must not return the admin uid unless an explicit trusted-email-linking policy is enabled.

High: banned or suspended NodeBB users are not checked before SSO success

Affected: lib/identity.js (lines 205-227 and 286-317), lib/strategy.js (lines 91-104)

Exploit scenario: A previously banned local user has a linked authentikSub, or has an email that matches a new verified Authentik login. The plugin resolves the uid and calls strategy.success without checking NodeBB ban/suspension status, potentially allowing SSO to bypass restrictions that local login would enforce elsewhere.

Why unsafe: Authentication plugins must preserve NodeBB account restrictions. Returning success for banned/suspended/deactivated users can restore access despite moderation or administrative controls.

Exact fix: Before returning { uid } from identity.resolve or before strategy.success, query the NodeBB user state using the appropriate NodeBB 4.x APIs/fields for banned, suspended, disabled, or deleted accounts. Fail closed if the account is restricted. Add the same check before linking a matched email account.

Regression test: Previously banned user with authentikSub logs in through OIDC and is rejected. Existing banned local user with matching verified email and no authentikSub is not linked and not logged in.

Medium: local email confirmation state is not required before automatic verified-email linking

Affected: lib/identity.js (lines 302-307)

Exploit scenario: A local NodeBB account has email victim@example.com but email:confirmed is false. An Authentik user signs in with victim@example.com and email_verified true. The plugin links the Authentik sub and then calls user.email.confirmByUid, upgrading the local email confirmation state and returning the uid.

Why unsafe: This treats Authentik email verification as proof of ownership for the existing NodeBB account. That may be valid only under a deliberate account-migration policy. As a default, it can convert stale or untrusted local email records into SSO account ownership.

Exact fix: If automatic verified-email linking remains available, require the target local account email to already be confirmed, or require explicit logged-in account linking. Do not call confirmByUid as part of silent linking unless trusted-IdP-email-linking is enabled.

Regression test: Existing local account with email:confirmed = 0 and matching verified Authentik email must not be linked silently under safe defaults.

Medium: deleted-user recovery can fall back to verified-email linking

Affected: lib/identity.js (lines 205-210 and 526-era tests in test/identity.test.js)

Exploit scenario: A sub mapping points to a deleted uid. The plugin deletes the stale sub mapping and continues with email-based resolution. If another local account with the same verified email exists, the same Authentik subject can be linked to that account.

Why unsafe: Deletion should be a hard lifecycle boundary unless an administrator explicitly repairs a mapping. Automatically falling through from a stale sub mapping to email linking can unintentionally resurrect or reassign an external identity after account deletion.

Exact fix: When a sub mapping points to a missing/deleted uid, fail closed and require admin repair instead of continuing to email linking. If automatic repair is desired, make it an explicit admin action with audit logging.

Regression test: Stale sub mapping to deleted uid plus matching email on another local account should reject and leave mappings unchanged under safe defaults.

Medium: display-name/fullname sync can enable privileged-user impersonation

Affected: lib/sync.js (lines 17-37), lib/config.js syncFullnameOnLogin setting

Exploit scenario: Authentik returns name = "Admin" or a moderator-like display name. If syncFullnameOnLogin is enabled, the plugin writes that value to the NodeBB fullname for the linked account. A normal user can visually impersonate staff in views that display fullname prominently.

Why unsafe: This is not privilege escalation by itself, but identity presentation is security-sensitive in a forum. Provider-controlled display names should not be allowed to mimic administrators, moderators, system accounts, or reserved names without policy.

Exact fix: Add reserved-name checks for synced fullname/display fields, or restrict fullname sync to trusted provider-managed directories with a warning. Consider never syncing display names for accounts with existing local profile customizations unless explicitly enabled per field.

Regression test: With syncFullnameOnLogin enabled, provider name "Admin" or a configured reserved moderator name is rejected or not applied for a non-admin uid.

Medium: required takeover regression tests are missing

Affected: test/identity.test.js

Exploit scenario: Future changes could weaken email_verified handling, collision checks, or admin-account linking behavior without detection.

Why unsafe: Account linking is the highest-risk NodeBB-specific area. The current test suite covers several good cases, but it does not cover all dangerous account-takeover cases called out in this audit.

Exact fix: Add focused identity tests for privileged/local-account and banned/deleted states.

Regression tests to add:

- Attacker creates Authentik account with victim email while email verification is disabled or email_verified false: no link, no user creation.
- Attacker changes Authentik email to existing admin email: no admin account link under safe defaults.
- Two IdP users share the same verified email: first link may only happen under explicit policy; second must fail closed.
- Existing local NodeBB admin has same email as new OIDC user: admin uid is not returned by automatic linking.
- Previously banned/suspended user logs in through OIDC: login is rejected.
- Deleted user with stale sub mapping cannot be silently reassigned through email fallback.

----

Role/group mapping audit - 2026-05-09

Confirmed controls:

- No Authentik group/role to NodeBB group/admin mapping is currently implemented in lib/.
- normalizeClaims keeps only sub, email, email_verified, preferred_username, name, and sid. It drops groups, roles, and arbitrary custom claims.
- syncProfile only supports optional fullname sync. It does not add users to NodeBB groups, grant admin/moderator privileges, or read group/role claims.
- identity.resolve does not grant roles. It only resolves or creates a uid.
- Default role behavior is least privilege with respect to Authentik claims: missing, malformed, or malicious groups/roles claims are ignored because no role sync exists.
- Existing planning docs correctly treat role/group sync as future high-risk work requiring explicit mapping rows, direction, removal policy, dry run, and privileged-role guardrails.

No current role/group privilege-escalation finding

Affected: lib/oidc.js (lines 258-270), lib/sync.js (lines 17-37), lib/identity.js (lines 286-318)

Exploit scenario checked: Authentik returns groups such as ["admin"], ["not-admin"], malformed groups, or user-controlled profile fields that include "admin". Current code drops those claims and does not call NodeBB group/admin APIs, so they do not grant elevated access.

Why this is currently safe: There is no mapping implementation and no substring/regex/case-insensitive role matching code to exploit.

Regression test: Add a defensive test that normalizeClaims drops groups and roles and identity/profile sync do not alter NodeBB group membership when groups/roles claims are present.

Medium: future role/group mapping needs explicit exact-match guardrails before implementation

Affected: planned feature; docs/IMPLEMENTATION_PLAN.md (lines 558-578), docs/NEXT_STEPS.md role/group sync sections

Exploit scenario: A future implementation maps Authentik groups to NodeBB privileges using substring checks such as groups.join(',').includes('admin'), case-folding without policy, or regex built from admin-entered values. A user with group "not-admin", "Admin" under ambiguous case rules, or a crafted group string could receive admin/moderator access.

Why unsafe: Role/group mapping directly changes authorization. Any ambiguity in matching, claim source, case handling, or removal behavior can grant or retain elevated forum access.

Exact fix: When implementing, only trust groups/roles from the validated ID token or trusted UserInfo response after identity resolution by issuer + sub. Require exact string matching against configured Authentik group/role identifiers. Do not use substring matching, untrusted regex, or user-editable profile fields. Make admin/moderator mappings disabled by default and require explicit confirmation. Define case behavior per mapping. Define removal behavior per mapping and audit drift.

Regression tests to add when implemented:

- group "not-admin" does not grant admin.
- group "Admin" behavior is explicit according to configured case policy.
- missing groups claim grants no elevated access.
- malformed groups claim grants no elevated access.
- user-controlled profile/custom field named admin grants no elevated access.
- admin/moderator mapping requires explicit opt-in.
- removed Authentik group removes/revokes corresponding NodeBB group on next login when removal is configured.
- removed Authentik group does not remove NodeBB group when mapping is add-only/manual-removal.

----

NodeBB session creation after OIDC success audit - 2026-05-09

Confirmed controls:

- The plugin does not manually set session cookies, write req.session.uid, call res.cookie, or implement its own session store.
- The plugin registers an official NodeBB/Passport SSO strategy through plugin.initAuth, passport.use, and the strategies array with url and callbackURL.
- After OIDC validation and identity resolution, lib/strategy.js calls this.success(nodebbUser) with the resolved { uid } object. Session creation is delegated to NodeBB/Passport rather than custom plugin code.
- The callback path does not accept uid from req.query or req.body. The returned uid comes from identity.resolve after state, token, ID-token, UserInfo, and account-linking checks.
- No plugin code was found that configures cookie HttpOnly, Secure, or SameSite attributes. Those are controlled by NodeBB/Express deployment configuration, not this plugin.

Medium: session regeneration after OIDC login is delegated to NodeBB but not verified by plugin tests

Affected: lib/strategy.js (line 104), library.js (lines 121-138), test/strategy.test.js

Exploit scenario: If NodeBB's auth strategy handling did not regenerate the session on SSO success, an attacker who fixed a victim's anonymous session id before login could retain knowledge of the session id after OIDC authentication.

Why unsafe: Session fixation is a core web-login risk. The plugin correctly delegates login to NodeBB/Passport, but this repository has no regression test proving the pre-login anonymous session id changes after OIDC success in the target NodeBB 4.x runtime.

Exact fix: Confirm the NodeBB 4.x SSO strategy flow calls the official login/session API that regenerates sessions on successful authentication. Add an integration test against a running NodeBB test app or a route-level harness that captures the session id before login and after callback.

Regression test: Start with an anonymous session, complete OIDC callback successfully, and assert the post-login session id differs from the pre-login session id.

Medium: cookie security attributes are deployment-controlled and not validated by plugin tests/docs

Affected: NodeBB deployment/session configuration; no plugin-owned cookie code found

Exploit scenario: In production, if NodeBB is deployed with insecure cookie settings, the SSO-created session cookie could be readable by JavaScript, sent over HTTP, or sent cross-site in unsafe contexts.

Why unsafe: OIDC login can be protocol-correct while the resulting web session remains vulnerable if cookies are missing HttpOnly, Secure, or appropriate SameSite attributes.

Exact fix: Document required production cookie posture for this plugin: HttpOnly enabled, Secure enabled behind correct HTTPS/proxy configuration, and SameSite=Lax unless NodeBB has a reviewed reason for a different setting. Add a deployment check or admin diagnostic if NodeBB exposes session cookie config.

Regression test: Browser/integration test after successful OIDC login asserts the NodeBB session Set-Cookie includes HttpOnly, Secure in production, and SameSite=Lax or the reviewed configured value.

Low: forced code/state login-CSRF/session-fixation regression coverage is missing

Affected: test/strategy.test.js, test/state.test.js

Exploit scenario: An attacker tries to start an OIDC login in their own browser, then force the victim's browser to hit the callback with the attacker's code/state. Correct behavior requires the state to be bound to the victim's browser session and the callback to reject because the attacker's state is absent from the victim session.

Why unsafe: The implementation stores state in req.session and consumes it, which is the right design, but the regression suite does not fully exercise a forced cross-browser callback at the strategy/session level.

Exact fix: Add tests with two separate req.session objects. Create state in attacker session, then call callback in victim session with attacker's state/code and assert state.consume fails, exchangeCode is not called, and strategy.success is not called.

Regression tests to add:

- session fixation attempt fails.
- pre-login session id changes after login.
- callback cannot log attacker into victim's browser via forced code/state flow.

----

CSRF and login-CSRF audit - 2026-05-09

Confirmed controls:

- OAuth callback state is stored in req.session.authentikOidc, so it is bound to the browser session that started login.
- Callback state is consumed with stateStore.consume before token exchange and deleted on first use.
- Missing or wrong state throws before token exchange.
- State entries expire after 10 minutes and the session stores at most five outstanding login attempts.
- Provider error callbacks are handled before state/token/user resolution and do not create a NodeBB session.
- The plugin has no user-facing account-link/disconnect mutation endpoint. The linked-account profile page is read-only and requires an authenticated session plus account permissions.
- Admin POSTs from public/admin.js include x-csrf-token: config.csrf_token.
- OIDC back-channel logout is POST-only, rejects logout_token in query string, validates a signed logout token, requires issuer/audience/JWKS validation, and rejects replayed jti values.

Medium: login initiation can still be used for account confusion because silent verified-email linking is supported

Affected: lib/strategy.js (lines 36-70), lib/identity.js (lines 302-309)

Exploit scenario: An attacker sends a victim a link to /auth/authentik. The victim completes Authentik login or enrollment in a browser with confusing upstream session state. If the returned verified email matches an existing local account, the plugin can silently link that Authentik subject to the local account. This is not classic missing-state login CSRF, but login initiation is still a cross-site GET that can drive a sensitive account-linking flow.

Why unsafe: OAuth state protects the callback from attacker-created state, but it does not ensure the user intended to link an Authentik identity to an existing NodeBB account. Silent verified-email linking makes login initiation part of account binding.

Exact fix: Make existing-account linking an explicit authenticated NodeBB flow with CSRF protection, or require an admin-enabled trusted-email-linking policy. For regular /auth/authentik starts, safe default should create/link only by issuer + sub and avoid binding to an existing local account solely because email matches.

Regression test: Victim starts login from a cross-site link and Authentik returns a new sub with victim's verified email. Under safe defaults, assert the existing NodeBB account is not linked unless an explicit CSRF-protected account-link flow or trusted-email-linking policy is active.

Medium: admin API CSRF protection is assumed from NodeBB route helpers but not asserted in plugin tests

Affected: library.js (lines 29-94), public/admin.js (lines 25-35)

Exploit scenario: If routeHelpers.setupApiRoute does not enforce CSRF for plugin POST routes in the target NodeBB version, an attacker could trick an authenticated admin into changing OIDC settings, running discovery/JWKS tests, or repairing mappings.

Why unsafe: Settings changes can redirect authentication to attacker-controlled infrastructure, weaken TLS/dev settings, or alter account-linking behavior. Mapping repair can modify identity-link state. These routes must require both admin privileges and CSRF.

Exact fix: Verify NodeBB 4.x setupApiRoute applies CSRF protection to POST routes, or explicitly add the NodeBB CSRF middleware to admin POST middlewares. Keep public/admin.js sending x-csrf-token.

Regression test: POST /api/v3/plugins/authentik-oidc/settings, /discover, /jwks/test, and /mappings/repair-stale without CSRF token must return 403 or the NodeBB CSRF failure response.

Low: forced attacker-state callback is not covered at strategy level

Affected: test/state.test.js, test/strategy.test.js

Exploit scenario: Attacker starts login in their own browser, obtains state/code, and sends the callback URL to the victim. The victim's session does not contain that state, so the callback should fail before token exchange. The state helper behavior supports this, but the strategy tests do not prove exchangeCode and success are skipped in this exact scenario.

Why unsafe: This is the classic OAuth login-CSRF regression case. A future refactor could weaken session-bound state handling without being caught by the current strategy test suite.

Exact fix: Add a strategy-level test using two separate session objects. Create state in attacker session, then call authenticate with victim session and attacker's state/code. Assert state.consume fails, exchangeCode is not called, and success is not called.

Regression test: login callback with attacker-created state fails in victim session.

Low: back-channel logout is intentionally CSRF-exempt but should be documented as token-authenticated server-to-server POST

Affected: library.js (line 19), lib/logout.js (lines 141-195)

Exploit scenario: A browser can POST to /auth/authentik/backchannel-logout cross-site, but without a valid signed logout_token the request is rejected or ignored. This is the correct model for OIDC back-channel logout, but it should be documented so future maintainers do not add cookie-session side effects to this unauthenticated endpoint.

Why unsafe: Back-channel logout cannot require a browser CSRF token because Authentik posts server-to-server. Its safety depends entirely on method restriction, signed logout-token validation, issuer/audience checks, and replay rejection.

Exact fix: Document that back-channel logout is CSRF-exempt by design and must remain limited to signed logout-token processing. Keep rejecting query-string logout tokens and non-POST methods.

Regression test: Browser-style POST without logout_token does not revoke sessions. GET with logout_token in query does not revoke sessions. Valid signed logout_token over POST revokes only the mapped uid.

Medium: PKCE verifier is not guaranteed for every login

Affected: lib/state.js (line 25), lib/strategy.js (line 37)

Exploit scenario: If settings.usePkce is false, login-start generates no code_verifier, authorization omits code_challenge, and token exchange omits code_verifier.

Why unsafe: RFC 9700 expects Authorization Code Flow clients to use PKCE, including confidential clients unless there is a strong documented reason.

Exact fix: Remove the usePkce runtime toggle or make it impossible to disable in normal config. Always generate a fresh verifier and send code_challenge_method=S256.

Regression test: Add a test that starts login with settings containing usePkce: false and asserts the authorization URL still includes code_challenge and code_challenge_method=S256, and the session stores a non-empty codeVerifier.

Medium: state generation can accept caller-provided state

Affected: lib/state.js (line 21), lib/strategy.js (line 37)

Exploit scenario: If the Passport/NodeBB caller ever passes predictable or reused options.state, the plugin stores that value instead of generating its own high-entropy state. Concurrent attempts using the same supplied value in the same session would overwrite the previous nonce/code verifier.

Why unsafe: The plugin should own the OIDC state value. “Every login attempt generates fresh high-entropy state” is not guaranteed while external state is accepted.

Exact fix: Change stateStore.create(req, state, ...) to always generate stateKey = randomString() and remove the state parameter unless there is a proven NodeBB integration requirement.

Regression test: Call stateStore.create(req, 'fixed-state') twice and assert neither returned state equals 'fixed-state', both states differ, and both entries remain present with distinct nonce/verifier values.

Low: test coverage does not fully prove session binding/concurrent isolation

Affected: test/state.test.js (line 8)

Exploit scenario: A future refactor could move state into a shared object or overwrite session entries, and current tests would not catch all cross-session/cross-attempt failures.

Why unsafe: The implementation is currently session-bound, but the regression suite only covers missing state and reuse. It does not explicitly cover wrong state, another session’s state, or two simultaneous attempts.

Exact fix: Add focused state tests.

Regression tests to add:


callback without state is rejected: already covered.

callback with wrong state is rejected.

callback with reused state is rejected: already covered.

callback with state from another session is rejected.

two simultaneous login attempts in the same session keep distinct state, nonce, codeVerifier, and consuming one does not delete or alter the other.

----

## Logout behavior audit - 2026-05-09

Confirmed controls:

- The plugin does not register a NodeBB local logout override. Local browser logout is delegated to NodeBB, so plugin IdP logout failures cannot block NodeBB's normal local logout path unless a future route/hook is added.
- The plugin supports OIDC back-channel logout at POST /auth/authentik/backchannel-logout when explicitly enabled.
- The back-channel route rejects logout_token in query strings, accepts body/form tokens, does not log the raw token, and records only sanitized diagnostics.
- Back-channel logout token validation requires JWKS signature validation, an asymmetric algorithm allowlist, exact issuer, audience, azp when applicable, the standard back-channel logout events claim, no nonce, sub or sid, iat freshness, and jti.
- Back-channel logout replay is rejected with a DB-backed jti cache.
- Unknown sub/sid is harmless: the handler records an unmatched diagnostic and returns 204 without revoking sessions.
- The pre-login Authentik session-clear redirect uses a trusted configured/discovered logout or invalidation endpoint and a plugin-built return target. It does not use arbitrary returnTo/next request parameters.
- The plugin does not use id_token_hint for logout, so it does not currently expose a stored ID token through logs or redirect URLs.

Medium: back-channel logout revokes every NodeBB session for the mapped uid, not only the affected OIDC sid/session

Affected: lib/logout.js (lines 176-180), lib/identity.js sid mapping helpers

Exploit scenario: A user is logged into NodeBB on several devices or has both local and OIDC-created sessions. Authentik sends a valid back-channel logout token for one OIDC provider session sid. The plugin maps sid/sub to a uid and calls user.auth.revokeAllSessions(uid), logging the user out everywhere, including sessions not tied to that Authentik sid.

Why unsafe: OIDC back-channel logout should target the affected RP session when sid is available. Revoking all sessions is conservative, but it is broader than the logout signal and can create avoidable account-wide denial of service. It also prevents the regression guarantee "logout for one user/session does not log out everyone" from being tightened to "only the affected session is logged out."

Exact fix: Store the NodeBB session id that was established by each OIDC login alongside the Authentik sid, for example sid -> { uid, sessionId }. On a logout token with sid, revoke only that session id if NodeBB exposes a session-specific revocation API. Fall back to uid-wide revocation only for sub-only logout tokens or when no session-specific API is available, and document that fallback explicitly.

Regression test: Create two NodeBB sessions for the same uid, map only one to sid-1, send a valid logout token with sid-1, and assert only that mapped session is revoked. Add a separate sub-only logout test that asserts the broader configured fallback behavior.

Medium: logout subject mapping is not issuer-qualified

Affected: lib/logout.js (lines 125-136), lib/identity.js subject mapping storage

Exploit scenario: The administrator changes issuer configuration, migrates between Authentik applications, or imports stale mappings. A valid logout token from the currently configured issuer contains sub value X. Because uidFromLogoutToken resolves only by sub, it can revoke sessions for a NodeBB account whose stored mapping was created under a different issuer but shares the same sub.

Why unsafe: The safe OIDC external identity key is issuer + sub. Exact issuer validation on the logout token proves which issuer created the logout signal, but the lookup discards that issuer when choosing which NodeBB uid to revoke.

Exact fix: Store and resolve OIDC subject mappings by issuer + sub. Pass settings.issuer into uidFromLogoutToken and call an issuer-qualified lookup before falling back to any legacy sub-only mapping. Provide a one-time migration/repair path for existing mappings.

Regression test: Create two mappings with the same sub under different issuers. Configure issuer A, send a valid logout token from issuer A, and assert only the issuer A mapping is revoked. Repeat for issuer B.

Low: local logout and RP-initiated IdP logout behavior is delegated/documented but not regression-tested

Affected: library.js (init routes), README.md, docs/AUTHENTIK_SETUP.md

Exploit scenario: A future change adds a NodeBB logout hook or redirect to Authentik's end_session_endpoint and accidentally makes local logout depend on a successful IdP redirect, or accepts an attacker-controlled post_logout_redirect_uri. Users could fail to log out locally when Authentik is down, or be sent to an attacker-controlled URL after logout.

Why unsafe: Local logout must destroy the NodeBB session regardless of IdP availability. RP-initiated logout, if added later, must use a fixed allowlisted post_logout_redirect_uri built from the NodeBB public URL and must not accept user-controlled redirect targets.

Exact fix: Keep the current NodeBB-local logout path independent from IdP logout unless RP-initiated logout is deliberately implemented. If implementing it, destroy/regenerate the NodeBB session first, then optionally redirect to the trusted discovered end_session_endpoint with a fixed post_logout_redirect_uri. Do not accept returnTo, next, callback, or post_logout_redirect_uri from the request.

Regression test: Simulate local NodeBB logout while the Authentik end-session endpoint is unavailable and assert the NodeBB session/cookies are cleared. Add a route-level test that logout redirect cannot target https://evil.com through any request parameter.

Low: fake back-channel logout token rejection is not tested end-to-end

Affected: test/logout.test.js, test/oidc.test.js

Exploit scenario: A future refactor weakens the real logout token verification path while handler tests continue to mock oidc.verifyLogoutToken and token-validation tests continue to mock JWT/JWKS behavior. A malformed or unsigned logout token might begin reaching session revocation without a failing regression test.

Why unsafe: Back-channel logout is CSRF-exempt and unauthenticated at the HTTP layer by design. Its only authorization boundary is logout-token validation, so tests should exercise the real verifier through the HTTP handler for invalid tokens.

Exact fix: Add an integration-style handler test that uses the real oidc.verifyLogoutToken path with a JWKS mock and sends malformed, unsigned, wrong-issuer, wrong-audience, and unknown-kid logout tokens. Assert 400 and no session revocation.

Regression test: POST /auth/authentik/backchannel-logout with logout_token=fake-token while back-channel logout is enabled must return 400 and leave revokedSessionsForUids empty.

Low: provider logout/session-clear return-target safety is covered indirectly but should have an explicit evil.com regression

Affected: lib/strategy.js (lines 35-57), lib/oidc.js providerLogoutUrl

Exploit scenario: The current production caller builds returnTo from either the fixed plugin login URL or a provider-relative authorization URL. A future change could pass a request-controlled returnTo into providerLogoutUrl, causing Authentik to redirect to an attacker-controlled post-logout target if Authentik accepts it.

Why unsafe: Logout redirects are common open-redirect sources. Even when the provider enforces allowlists, the relying party should not generate untrusted post_logout_redirect_uri or next values.

Exact fix: Keep providerLogoutUrl as a low-level helper, but enforce at the strategy call site that returnTo is built only from config.getLoginUrl() or providerRelativeUrl(authorizationUrl, providerLogoutEndpoint). Add a test that request query parameters named returnTo, next, callback, redirect, and post_logout_redirect_uri do not appear in the generated logout/session-clear URL.

Regression test: Start login with clearProviderSessionBeforeLogin enabled and request ?next=https://evil.com&post_logout_redirect_uri=https://evil.com. Assert the redirect target's return parameter is still the fixed plugin login URL or provider-relative authorization URL, never evil.com.

----

## Token storage audit - 2026-05-09

Confirmed controls:

- Access tokens are used only as transient local values after code exchange. lib/strategy.js passes tokenSet.access_token into ID-token at_hash validation and optional server-to-server UserInfo, then discards the token.
- ID tokens are used only as transient local values for validation and claim extraction. The plugin does not store raw ID tokens.
- Refresh tokens are not referenced by implementation code and are not stored.
- There is no browser localStorage/sessionStorage use in public/admin.js or templates.
- Tokens are not exposed to templates or client-side JavaScript. The linked-account page renders only provider metadata such as issuer, timestamps, last provider email, and external self-service links.
- The ACP diagnostics deliberately store claim metadata and sanitized redirect URLs, not raw access tokens, refresh tokens, ID tokens, authorization codes, state, nonce, or PKCE verifier values.
- logger.safeMeta drops metadata keys containing secret, token, or code before writing plugin logs.
- Database writes observed in identity/profile/logout code store subject mappings, sid mappings, issuer, timestamps, and last provider email; no access_token, refresh_token, id_token, or token-set fields are written.

Low: refresh tokens can be requested through configurable scopes even though the plugin does not need them

Affected: lib/config.js DEFAULTS/scopes and validate (lines 19 and 160-164), lib/oidc.js authorizationUrl (lines 302-320)

Exploit scenario: An administrator or compromised admin session sets scopes to "openid email profile offline_access". Authentik may issue a refresh_token during the code exchange. The plugin does not store it, but the token is still minted, transmitted to NodeBB, present in process memory in tokenSet, and potentially visible to infrastructure that captures token endpoint responses.

Why unsafe: A NodeBB forum SSO plugin only needs OIDC long enough to establish the NodeBB session. Requesting offline access expands the token surface and grants long-lived authority that the plugin does not use. The safest default is to avoid refresh-token issuance entirely.

Exact fix: Reject offline_access in config.validate unless a future feature explicitly requires refresh tokens and adds encrypted at-rest storage, rotation, least-privilege scope review, and tests. Also document that the recommended scope set is "openid email profile" and that refresh tokens are intentionally unsupported.

Regression test: Saving settings with scopes containing offline_access must fail with a validation error. Starting login with default settings must produce an authorization URL whose scope does not contain offline_access.

Low: token non-persistence is mostly implicit and needs regression coverage

Affected: lib/strategy.js authenticate callback branch (lines 74-99), lib/diagnostics.js recordFailure/recordAuthorizationStart, public/admin.js diagnostics renderers

Exploit scenario: A future diagnostic, profile page, sync feature, or troubleshooting log starts storing tokenSet, raw idClaims, raw userinfoClaims, or token endpoint responses in NodeBB DB or ACP output. Because the current "discard tokens after login" behavior is not asserted end-to-end, the regression may be missed.

Why unsafe: Access tokens and refresh tokens are bearer credentials. ID tokens can contain sensitive identity claims and may be accepted by logout or downstream integrations as proof material. Persisting or rendering them increases blast radius after DB compromise, XSS, admin-panel exposure, or log aggregation leaks.

Exact fix: Add explicit tests and code comments at the token boundary: exchangeCode returns tokenSet, strategy consumes only access_token/id_token, and no token fields are passed to identity.resolve, profileSync.syncProfile, diagnostics, templates, or logger metadata. Keep diagnostics metadata-only.

Regression test: Simulate a token response containing access_token, refresh_token, id_token, token_type, and expires_in. Complete a login failure after ID-token/UserInfo claim extraction and assert database diagnostics, logger calls, rendered ACP diagnostics, and user fields do not contain any raw token values.

----

## Logging and error handling audit - 2026-05-09

Confirmed controls:

- No direct plugin log call was found that logs req.query.code, access_token, refresh_token, id_token, client_secret, Authorization headers, cookies, or the full callback URL.
- lib/logger.js filters top-level metadata keys containing secret, token, or code before writing to Winston.
- Callback provider errors log only req.query.error, not error_description, code, state, or the full callback URL.
- Token endpoint exchange is server-to-server. The plugin does not log the authorization code before exchange.
- UserInfo sends Authorization: Bearer access_token server-to-server, and lib/http.js strips Authorization/Cookie/Proxy-Authorization headers when following cross-origin GET/HEAD redirects.
- Authorization-start diagnostics sanitize state, nonce, and code_challenge out of stored redirect URLs.
- Failure diagnostics store claim metadata only, not raw token values or full claim payloads.

Medium: callback error path can log raw stack/message from lower-level errors

Affected: lib/strategy.js catch block (lines 107-123), lib/http.js requestJson/requestText error messages

Exploit scenario: A misconfigured or malicious token endpoint, JWKS endpoint, proxy, or lower-level library returns/throws an error whose message includes a full URL, request body, Authorization header, token response, or other secret-bearing text. The strategy catch block logs err.stack || err.message for error-level failures, and diagnostics stores err.message for ACP display.

Why unsafe: The plugin currently avoids deliberately logging code/access_token/id_token/client_secret, but raw upstream error text is not a safe boundary. Authorization codes, client_secret values, bearer tokens, cookies, and full callback URLs often appear in exception messages from HTTP clients, proxies, and debugging middleware. Once written to NodeBB/Winston logs or ACP diagnostics, they are harder to contain.

Exact fix: Introduce a central sanitizeErrorForLog(err) helper. It should remove or replace URL query strings, form parameters named code/client_secret/code_verifier/access_token/refresh_token/id_token/logout_token/state/nonce, Authorization and Cookie header values, JWT-like strings, and long opaque bearer-like values. In lib/strategy.js, log a sanitized code/category plus sanitized message; avoid raw stack in production or sanitize every stack line before logging. In diagnostics.normalizeError, store the sanitized message only.

Regression test: Simulate exchangeCode throwing Error("HTTP 400 from https://auth.example.com/token?code=secret-code&client_secret=secret-client-secret access_token=secret-access id_token=secret-id"). Assert logger.error, diagnostics.getLastFailure(), and the error returned to Passport do not contain secret-code, secret-client-secret, secret-access, or secret-id.

Medium: logger metadata redaction is shallow and key-based only

Affected: lib/logger.js safeMeta (lines 11-22), lib/admin.js testJwks catch (lines 72-79), lib/strategy.js diagnostic/profile-sync warning logs

Exploit scenario: Code logs metadata under a safe-looking key such as message, url, error, headers, or details, and that value contains "Authorization: Bearer ...", "Cookie: ...", "client_secret=...", or "code=...". logger.safeMeta allows the value because only the metadata key is checked. Nested objects and arrays are also not recursively redacted.

Why unsafe: Key-name filtering catches obvious mistakes such as { code: ... } or { access_token: ... }, but it misses the common case where secret material is embedded in exception messages, URLs, nested objects, or header maps. This is exactly how token endpoint and proxy failures tend to surface.

Exact fix: Replace safeMeta with recursive redaction. Redact by key and by value. For strings, strip sensitive URL/form parameters, redact Authorization/Cookie header patterns, and replace JWT-like three-part base64url tokens and long opaque bearer strings. Apply the same sanitizer to logger message/error arguments where practical.

Regression test: Call logger.warn("test", { message: "Authorization: Bearer abc.def.ghi client_secret=s3 code=c0", nested: { headers: { cookie: "sid=secret" } } }) with a mocked Winston sink. Assert the captured log contains none of abc.def.ghi, s3, c0, or sid=secret.

Low: JWKS/admin diagnostic errors can echo secret-bearing URLs back to admins/logs

Affected: lib/admin.js testJwks (lines 55-79), lib/http.js requestJson errors, public/admin.js alert rendering

Exploit scenario: An admin pastes a JWKS URI or issuer URL containing a credential-like query string, or a failing HTTP request includes the full URL in err.message. The JWKS test route logs { jwksUri, message: err.message } and may return err.message to the browser. logger.safeMeta does not filter jwksUri, and public/admin.js displays returned error text.

Why unsafe: Admin-only exposure is still exposure. URLs frequently carry temporary credentials during troubleshooting, and those values can land in logs, ACP responses, screenshots, or support tickets.

Exact fix: For all admin diagnostics and HTTP helper errors, render/log sanitized URL origins plus path without query/fragment unless a specific safe query parameter is needed. Never echo full arbitrary diagnostic URLs in error messages. Consider returning stable error codes plus concise safe messages.

Regression test: POST the JWKS test route with jwksUri=https://auth.example.com/jwks?client_secret=secret&access_token=token and force a request failure. Assert the HTTP response and log output do not contain secret or token.

Low: PII is logged for some account-linking failures

Affected: lib/identity.js getUidByEmail/resolve (lines 123-125 and 298-299)

Exploit scenario: A user attempts SSO with an unverified email or the plugin detects duplicate email mappings. The plugin logs normalized email addresses in warning metadata.

Why unsafe: Email addresses are not OAuth tokens, but they are personal data and account-identifying material. Authentication failure logs are commonly retained longer and exposed to more operators than user profile data.

Exact fix: Remove raw email from logs. Log booleans, uid counts, or a keyed one-way hash if correlation is needed. Keep exact email visibility in tightly permissioned account data, not operational logs.

Regression test: Simulate unverified-email and duplicate-email failure paths with person@example.com and assert Winston output does not contain the raw email address.

----

## Admin configuration safety audit - 2026-05-09

Confirmed controls:

- Client secret is never returned in cleartext through config.publicSettings; saved secrets are rendered back to the ACP as the placeholder "********".
- Leaving the client secret blank or as the placeholder preserves the existing saved secret.
- Client ID is required when the plugin is enabled.
- Client secret is required when the plugin is enabled, so the current implementation treats Authentik as a confidential-client setup.
- Issuer, authorization endpoint, token endpoint, UserInfo endpoint, JWKS URI, self-service URLs, end-session endpoint, and session-clear endpoint are validated as HTTPS URLs by default.
- Localhost HTTP is allowed only behind the explicit allowInsecureCallbackUrlForDevelopment setting, which defaults false.
- Private-network and localhost targets are rejected by default for provider/admin diagnostic URLs.
- Scopes must include openid.
- Callback URL and back-channel logout URL are computed from the configured NodeBB public URL, rendered read-only in the ACP, and validated when the plugin is enabled.
- Admin-controlled authorizationParameters cannot override protocol-critical parameters including client_id, redirect_uri, response_type, scope, state, nonce, code_challenge, or code_challenge_method.
- No "disable TLS validation" setting was found.
- No "skip token validation" setting was found.
- No "trust email without verification" setting was found. Email is accepted only when email_verified is exactly boolean true.
- Auto-create users behavior is explicit in the ACP through "Allow new SSO account creation".
- Role/group mapping is not implemented, so there is no current admin/moderator privilege mapping path and the default is no elevated role grant.

Medium: client_secret appears to be stored in normal NodeBB plugin settings, not a dedicated secret store

Affected: lib/config.js saveSettings/getSettings/publicSettings (lines 83-91 and 221-240), NodeBB meta.settings storage

Exploit scenario: An attacker gains read access to the NodeBB database, settings export, backup, or plugin settings table. Because clientSecret is stored with the rest of the plugin settings, the Authentik OAuth client secret can be recovered and used for confidential-client token endpoint requests.

Why unsafe: Masking the secret in the ACP prevents casual UI disclosure, but it does not protect at-rest storage. OAuth client secrets are credentials and should be stored using NodeBB's most secure available secret mechanism, or at minimum documented as database-resident sensitive data.

Exact fix: Check the target NodeBB 4.x APIs for a secure secrets/config facility. If available, store clientSecret there and keep only a reference/placeholder in meta.settings. If NodeBB has no encrypted secret store, document the limitation, require database backup protection, and consider environment-variable support such as AUTHENTIK_OIDC_CLIENT_SECRET that overrides DB settings.

Regression test: Save settings with clientSecret="secret-value", then call getSettings/publicSettings/admin render payload and assert the public/admin payload is masked. If a secure store is added, assert meta.settings no longer contains the raw secret.

Medium: "Allow HTTP callback URL for localhost development" also relaxes provider endpoint URL validation

Affected: lib/config.js validate (lines 148-180), templates/admin/plugins/authentik-oidc.tpl (lines 207-208)

Exploit scenario: An administrator enables "Allow HTTP callback URL for localhost development" expecting only the NodeBB callback URL check to allow local HTTP. The same flag is also passed to issuer, authorization, token, UserInfo, JWKS, end-session, session-clear, and self-service URL validation, allowing http://localhost provider endpoints. If accidentally left enabled outside local development, authorization codes, client_secret, and tokens can be sent over plaintext HTTP to a local or loopback endpoint.

Why unsafe: The setting label describes callback URL behavior, but the implementation broadens the security policy for all provider endpoints. That is a dangerous mismatch in an admin control because it can weaken token endpoint transport without clearly saying so.

Exact fix: Split this into narrowly scoped options. Prefer no broad dev toggle. If local development must be supported, use separate, clearly labeled controls such as "Allow HTTP NodeBB callback URL for local development" and "Allow HTTP loopback provider endpoints for local development", with the provider-endpoint option hidden behind explicit confirmation. Keep both disabled by default and reject non-loopback HTTP always.

Regression test: With only allowInsecureCallbackUrlForDevelopment enabled, saving tokenEndpoint=http://localhost:9000/token should fail unless a separate provider-endpoint development option is also explicitly enabled. HTTPS callback/provider settings should continue to pass.

Low: PKCE can be disabled from the admin UI

Affected: templates/admin/plugins/authentik-oidc.tpl (lines 202-205), lib/config.js DEFAULTS/normalizeSettings (lines 25 and 43), lib/state.js create, lib/oidc.js authorizationUrl/exchangeCode

Exploit scenario: An administrator disables "Use PKCE" for troubleshooting and forgets to re-enable it. The plugin continues Authorization Code Flow without code_challenge/code_verifier, weakening code injection/interception resistance.

Why unsafe: RFC 9700 recommends PKCE for authorization-code clients, including confidential clients. Exposing a routine admin toggle makes the insecure mode easy to leave enabled.

Exact fix: Remove the ACP toggle and always use S256 PKCE. If there is a temporary compatibility escape hatch, keep it out of normal UI, require an environment variable or explicit development-only setting, and show a high-severity warning.

Regression test: Render/load ACP settings and assert no ordinary admin field can disable PKCE. Save settings with usePkce=false and assert authorization still sends code_challenge_method=S256.

Low: admin settings validation lacks explicit tests for core required-field failures

Affected: test/config.test.js, lib/config.js validate

Exploit scenario: A future refactor accidentally stops requiring clientId, clientSecret, openid scope, HTTPS issuer, or a valid callback URL. The current tests cover several URL safety cases and settings toggles, but do not explicitly assert all required admin validation failures in one place.

Why unsafe: Admin configuration validation is part of the OIDC security boundary. Missing client_id, missing client_secret, non-HTTPS issuer, scopes without openid, or an invalid NodeBB public URL can break issuer/audience validation, confidential-client authentication, or redirect URI registration.

Exact fix: Add focused validation tests for the required admin safety rules: enabled plugin requires clientId, enabled confidential setup requires clientSecret, scopes must include openid, issuer and provider endpoints must be HTTPS unless explicit loopback development mode is enabled, and callbackUrl must be built from nconf url and validated.

Regression test: Parameterized config.saveSettings tests for each invalid field should reject with the expected field-level error. Add a test that changing request Host/X-Forwarded-Host has no effect on callbackUrl because it comes from the configured NodeBB URL.

Low: Authentik exact redirect URI matching is documented but not enforceable or tested from plugin settings

Affected: README.md, docs/AUTHENTIK_SETUP.md, templates/admin/plugins/authentik-oidc.tpl callbackUrl display

Exploit scenario: The plugin shows the correct callback URL, but Authentik is configured with a different or wildcard redirect URI. Depending on provider behavior, this can cause login failure or broaden where authorization codes may be sent.

Why unsafe: Exact redirect URI matching is a provider-side setting, but it is part of the relying party's deployment safety. The plugin cannot fully enforce Authentik's allowed redirect list through OIDC alone, but it should make the required exact value obvious and keep it covered in setup checks.

Exact fix: Keep callbackUrl read-only and copyable. Add explicit ACP/help text: "Register this exact URI in Authentik; do not use wildcards." If Authentik management API integration is ever added, validate the provider's registered redirect URI list against config.getCallbackUrl().

Regression test: Documentation/ACP snapshot test asserts the callback section tells admins to register the exact displayed URI in Authentik and avoid wildcard redirect URIs.

----

## Dependency audit - 2026-05-09

Reviewed:

- package.json has two direct runtime dependencies: jsonwebtoken ^9.0.3 and passport-strategy ^1.0.0.
- package-lock.json is present and tracked by git.
- npm audit --json completed successfully and reported 0 info, 0 low, 0 moderate, 0 high, and 0 critical vulnerabilities.
- npm metadata check: jsonwebtoken latest/current is 9.0.3, modified 2026-04-16, MIT licensed, repository github.com/auth0/node-jsonwebtoken.
- npm metadata check: passport-strategy latest/current is 1.0.0, modified 2022-06-23, repository github.com/jaredhanson/passport-strategy.
- Public advisory spot-checks found no direct known vulnerabilities for jsonwebtoken 9.0.3 or passport-strategy 1.0.0. Historical jsonwebtoken advisories affect older versions and are fixed in 9.0.0+.
- No deprecated request package dependency was found. HTTP calls use Node's built-in http/https modules through lib/http.js.
- No custom signature algorithm implementation was found. The plugin uses Node crypto for random state/nonce/PKCE verifier generation, SHA-256 PKCE challenges, and OIDC at_hash/c_hash calculation, and uses jsonwebtoken for JWT signature verification.
- No abandoned OIDC strategy dependency such as passport-openidconnect was found.

Medium: OIDC protocol handling is mostly custom instead of using a maintained OIDC relying-party library

Affected: lib/oidc.js, lib/strategy.js, package.json dependencies

Exploit scenario: A subtle OIDC validation requirement changes or is missed in local code: max_age/auth_time, exact issuer/discovery handling, nonce/state edge cases, azp/aud rules, JWKS cache behavior, token endpoint auth methods, logout-token rules, or new RFC 9700 guidance. A dedicated OIDC client library is more likely to encode and test these protocol details than bespoke code.

Why unsafe: jsonwebtoken is a JWT library, not an OIDC relying-party implementation. It verifies JWTs when called correctly, but the surrounding OIDC semantics are custom. The audit already found multiple protocol hardening gaps around PKCE configurability, ID-token required claims, discovery endpoint validation, callback handling, and token endpoint auth method.

Exact fix: Prefer a maintained OIDC/OAuth client library that supports NodeBB's CommonJS/runtime constraints, such as openid-client if compatible with the target NodeBB version. If the plugin keeps bespoke OIDC handling, maintain an explicit protocol conformance test suite covering Authorization Code + PKCE, discovery, issuer/audience/azp/nonce, token hashes, UserInfo, and back-channel logout.

Regression test: Add integration tests with real generated JWTs/JWKS and a fake OIDC provider exercising discovery, authorization URL generation, callback exchange, ID-token validation, UserInfo, and logout-token validation without mocking jwt.verify.

Low: passport-strategy is stable but old and should be monitored or avoided if NodeBB exposes an equivalent base

Affected: package.json dependency passport-strategy ^1.0.0, lib/strategy.js

Exploit scenario: A future Passport/NodeBB runtime change or security issue appears in the strategy base package, but the package remains low-churn and receives little maintenance. The plugin may carry an avoidable dependency for a very small abstraction.

Why unsafe: There is no current advisory signal here, and passport-strategy has no transitive dependencies, so risk is low. Still, an auth plugin should minimize reliance on stale auth-layer packages when the host platform may already provide the same abstraction.

Exact fix: Confirm whether NodeBB's bundled Passport exposes the Strategy base or whether extending passport-strategy remains the recommended pattern for NodeBB 4.x plugins. If NodeBB provides a stable base, remove the direct dependency. Otherwise keep it pinned through package-lock and monitor npm/GitHub advisories.

Regression test: Add a dependency policy check or documented release checklist item that confirms passport-strategy has no known advisories and remains compatible with the target NodeBB/Passport version before release.

Low: advisory review is not automated beyond npm audit

Affected: package.json, CI/release process

Exploit scenario: A vulnerability appears in OSV or GitHub Advisory Database before npm audit flags it locally, or the project releases without rerunning advisory checks. The current repo has no CI evidence of npm audit, OSV scan, or GitHub Dependabot/Advisory review.

Why unsafe: Dependency risk changes over time. A one-time manual audit is not enough for an authentication plugin because JWT/OIDC dependencies are security-critical.

Exact fix: Add a release/CI dependency audit step. At minimum run npm audit --omit=dev for production dependencies. Prefer adding OSV scanning against package-lock.json and enabling GitHub Dependabot security updates/advisory alerts for the repository.

Regression test: CI fails when npm audit reports any high/critical production advisory, and the release checklist records npm audit plus OSV/GitHub advisory review dates.

Low: package-lock is tracked, but dependency ranges still allow future minor/patch drift

Affected: package.json dependencies, package-lock.json

Exploit scenario: A developer runs npm install and refreshes package-lock to a newer transitive dependency. The semver ranges permit updates, which is normally useful, but auth/JWT dependency changes should be reviewed intentionally.

Why unsafe: Lockfiles control installed versions only when respected. Broad ranges plus casual lockfile refreshes can introduce unreviewed JWT, JOSE, or HTTP behavior changes.

Exact fix: Keep package-lock committed and require review for lockfile changes. Consider pinning security-critical direct dependencies exactly, or use a dependency update bot with tests and advisory context.

Regression test: Add CI using npm ci rather than npm install, and require package-lock.json changes to run the OIDC/JWT regression suite.

----

## NodeBB integration points audit - 2026-05-09

Reviewed integration points:

- Hook registration: plugin.json uses static:app.load, static:api.routes, filter:admin.header.build, filter:user.profileMenu, filter:auth.init, and filter:user.whitelistFields.
- Login route registration: filter:auth.init returns a Passport strategy descriptor with url /auth/authentik and callbackURL /auth/authentik/callback.
- Callback route registration: callback is delegated to NodeBB's auth strategy integration through filter:auth.init rather than a hand-registered Express callback route.
- Register route behavior: static:app.load adds router.get('/register', routing.handleRegisterRoute) to redirect anonymous registrations into OIDC when configured.
- Back-channel logout: static:app.load adds POST /auth/authentik/backchannel-logout.
- Admin settings: static:api.routes registers /api/v3/plugins/authentik-oidc/* routes with middleware.ensureLoggedIn plus a privileges.admin.can('admin:settings') check; admin page is registered through routeHelpers.setupAdminPageRoute.
- User creation: lib/identity.js uses NodeBB user.create with username/email/fullname.
- User lookup: uses user.getUidByEmail, user.getUidByUsername, user.exists, user.getUserField(s), plus batched DB scans for fallback/audit.
- External identity association: stores provider fields on user records and reverse mappings in NodeBB db objects: authentikSub, authentikIssuer, authentikLastLoginAt, authentikLastEmail, authentikLastSid, authentik:sub:uid, authentik:sub:<sub>.uid, and authentik:sid:uid.
- Session/state storage: state, nonce, and PKCE verifier are stored in req.session.authentikOidc and consumed from that same session on callback.
- Logout/session revocation: back-channel logout calls user.auth.revokeAllSessions(uid).
- Group assignment: no NodeBB group assignment or role mapping implementation was found.
- Reverse proxy: callback/login/back-channel URLs are built from NodeBB nconf url, not request Host or X-Forwarded-Host.

Confirmed controls:

- OIDC state/code_verifier is not stored in process-global memory. It is stored in req.session, so clustered NodeBB is safe when NodeBB is configured with its normal shared session store such as Redis/database-backed sessions.
- Cross-worker back-channel logout replay protection uses NodeBB database object fields, not process memory.
- The in-process JWKS cache stores public keys only. It may be stale per worker, but it is not secret-bearing and does not hold state/code_verifier.
- Public user-field whitelisting intentionally does not expose raw OIDC fields through filter:user.whitelistFields.
- Callback URL generation uses configured NodeBB public URL from nconf, supporting reverse proxy deployments when nconf url is set correctly.

Medium: direct /register route override may be brittle against NodeBB route ordering and plugin compatibility

Affected: library.js init (line 18), lib/routing.js handleRegisterRoute

Exploit scenario: NodeBB core or another plugin also registers /register. Depending on Express route order and NodeBB 4.x internals, this plugin may shadow the core route unexpectedly, be shadowed itself, or behave differently after a NodeBB upgrade. Invite-token or local-debug bypasses could regress if route ordering changes.

Why unsafe: Login and registration routes are security-sensitive. Hooking a core route directly is more brittle than using a documented NodeBB registration/auth customization hook if one exists for NodeBB 4.x. Route-order surprises can expose local registration when SSO-only behavior is intended or force OIDC when local/invite registration should remain available.

Exact fix: Verify the supported NodeBB 4.x API for registration-page interception or SSO registration behavior. Prefer a documented route/helper/hook over raw router.get('/register') if available. If direct route registration remains necessary, add integration tests that confirm route order and bypass behavior under the target NodeBB version.

Regression test: In a NodeBB 4.x integration harness, assert /register redirects to /auth/authentik only for anonymous normal registration, but does not redirect when local=1, invite token is present, registration is disabled/invite-only, or the user is already logged in.

Medium: NodeBB API compatibility is assumed through internal require paths and should be verified against the target NodeBB version

Affected: library.js, lib/identity.js, lib/logout.js, lib/profile.js, lib/mappings.js, lib/config.js

Exploit scenario: A NodeBB 4.x minor release changes routeHelpers.setupApiRoute semantics, user.auth.revokeAllSessions behavior, user.email.confirmByUid, user.create options, account helper signatures, privileges.admin.can, or internal require paths. The plugin can silently lose CSRF protection, fail to revoke sessions, create users with unexpected verification state, or expose/deny admin settings incorrectly.

Why unsafe: The plugin uses several NodeBB internal modules through require.main.require and module.parent.require. Some are common plugin patterns, but they are not all clearly stable public APIs from this audit alone. Authentication plugins need version-pinned integration tests because API drift becomes a security issue, not just a compatibility issue.

Exact fix: Validate every NodeBB integration against the exact target NodeBB 4.x version and document the supported API contract. Add a small NodeBB integration test or smoke-test matrix that boots the target NodeBB version with the plugin and exercises auth init, admin routes, user creation/linking, profile page, and back-channel logout.

Regression test: Against the supported NodeBB version, assert filter:auth.init registers a working strategy, admin API POST routes require admin + CSRF, user.create creates an unprivileged account with expected email verification state, and user.auth.revokeAllSessions removes active sessions.

Medium: database link lock can be left stuck after worker crash

Affected: lib/identity.js acquireDbLinkLock/withLinkLock (lines 151-171)

Exploit scenario: During account linking, a worker increments authentik:link-lock:uid and crashes before the finally block deletes the field. Future logins that need to link the same uid hit count > 1 and fail with concurrent-link indefinitely until an admin manually clears the field.

Why unsafe: The DB lock improves cross-process safety, but it has no TTL/lease owner. In clustered NodeBB, worker crashes, deploy restarts, or process kills can leave stale locks that create persistent login denial for affected users.

Exact fix: Use a TTL/lease-based distributed lock if NodeBB exposes one, or store lock owner + timestamp and treat expired locks as recoverable. Keep the in-process tail only as a local optimization. Add admin repair/audit visibility for stale link locks.

Regression test: Seed authentik:link-lock:uid for a uid with an expired timestamp/count, then attempt login/linking and assert the stale lock is reclaimed safely. Seed a fresh lock and assert concurrent linking still fails closed.

Low: session store dependency for clustered login should be documented and tested

Affected: lib/state.js, README.md/docs

Exploit scenario: A multi-process NodeBB deployment uses non-shared memory sessions or misconfigured sticky sessions. Login start stores state/nonce/code_verifier in one worker's req.session, but the callback lands on another worker without that session state. The callback fails as missing state. If an operator tries to "fix" this by weakening state validation, login CSRF/code injection risks return.

Why unsafe: The implementation is safe if NodeBB sessions are shared across workers, but clustered deployments depend on correct NodeBB session configuration. The plugin should explicitly require shared Redis/database-backed sessions rather than leaving operators to infer it.

Exact fix: Document that clustered NodeBB requires a shared session store for OIDC login, and add a startup/admin diagnostic if NodeBB exposes session-store metadata. Do not add process-memory fallback for OIDC state.

Regression test: Integration test with a shared session-store mock: create state in one strategy instance/process, consume it in another, and assert nonce/codeVerifier survive. A separate non-shared session test should fail closed with missing state.

Low: back-channel logout revocation depends on broad NodeBB user.auth.revokeAllSessions availability and semantics

Affected: lib/logout.js line 176

Exploit scenario: In a NodeBB version or session backend where user.auth.revokeAllSessions is absent, renamed, or only affects token sessions but not browser sessions, Authentik back-channel logout appears to succeed but does not actually terminate NodeBB browser sessions.

Why unsafe: Logout correctness is partly delegated to a NodeBB API whose behavior should be verified with the target session backend, especially Redis/database-backed sessions and clustered deployments.

Exact fix: At plugin init or back-channel logout handling, fail loudly if user.auth.revokeAllSessions is unavailable. Add a live/integration test that creates a NodeBB browser session, calls back-channel logout, and verifies the session can no longer access authenticated routes.

Regression test: With a Redis/database-backed session test fixture, log in a user, call back-channel logout for that uid, and assert the old session id is rejected on the next authenticated request.

Low: no group assignment implementation is present, but future role/group mapping must use NodeBB group APIs explicitly

Affected: future role/group sync work, docs/NEXT_STEPS.md

Exploit scenario: A future implementation writes group membership directly to DB keys or maps Authentik group strings to NodeBB admin/moderator roles without using supported NodeBB group/user APIs. This could bypass hooks, caches, slug normalization, privilege recalculation, or audit behavior.

Why unsafe: NodeBB group membership and admin/moderator privilege state are authorization-critical. Direct DB writes are likely to be incomplete and unsafe in clustered deployments.

Exact fix: When role/group mapping is implemented, use documented NodeBB group APIs only, keep mappings explicit and exact, and run cache/privilege updates through NodeBB's supported mechanisms. Keep default role least privilege.

Regression test: Future group mapping tests should assert group "not-admin" does not grant admin, missing/malformed groups grant no elevated access, group removal revokes NodeBB membership when configured, and changes propagate across clustered workers.

----

## Threat-model scenario simulation matrix - 2026-05-09

Verification run:

- npm test passed on 2026-05-09: 15 test files passed, 0 failed.

1. Attacker tries login CSRF

Outcome: Mostly blocked by session-bound state. Login start stores state/nonce/code_verifier in req.session.authentikOidc; callback consumes that state before token exchange. Existing finding remains: strategy-level cross-session attacker-state callback regression is missing.

Affected: lib/state.js, lib/strategy.js

Recommended regression test: Start login in attacker session, callback in victim session with attacker state/code, assert state.consume fails and exchangeCode is not called.

2. Attacker injects their authorization code into victim callback

Outcome: Blocked if state is not known for the victim session. If attacker lacks the victim's state, state.consume rejects before exchange. If code is swapped while state is valid, PKCE binds the code to the verifier stored in the victim session, but PKCE is currently admin-disableable.

Affected: lib/state.js, lib/oidc.js exchangeCode, lib/config.js usePkce

Recommended regression test: With PKCE enabled, exchange callback using valid victim state and attacker code whose verifier does not match; fake token endpoint must reject and strategy must not create a session. Also make PKCE non-disableable.

3. Attacker changes Host header to poison redirect_uri

Outcome: Blocked by design. redirect_uri/callbackUrl is built from nconf url in config.getCallbackUrl(), not req.get('host'), Host, or X-Forwarded-Host.

Affected: lib/config.js getCallbackUrl, lib/strategy.js

Recommended regression test: Call login start with Host: evil.com and X-Forwarded-Host: evil.com, assert authorization redirect_uri remains configured NodeBB URL.

4. Attacker replays a callback URL

Outcome: Blocked for a normal replay because state.consume deletes the state before token exchange. Existing test covers state single-use. Gaps remain around duplicate code/state parameters and callback-without-code behavior.

Affected: lib/state.js consume, lib/strategy.js callback branch

Recommended regression test: Replay same code/state callback twice through strategy; first reaches exchange, second fails before exchange. Add duplicate code/state rejection tests.

5. Attacker uses an ID token from another client_id

Outcome: Blocked by jwt.verify audience: settings.clientId, plus azp validation for multi-audience or explicit azp claims. Some tests cover azp behavior; wrong-audience real-JWT regression is still incomplete.

Affected: lib/oidc.js verifyIdToken/validateAuthorizedParty

Recommended regression test: Real signed ID token with aud "other-client" must be rejected.

6. Attacker uses an ID token from another issuer

Outcome: Blocked by jwt.verify issuer: settings.issuer. However, subject-to-uid mapping is still sub-only after verification, so issuer changes can still collide after a valid token from the current issuer is accepted.

Affected: lib/oidc.js verifyIdToken, lib/identity.js getUidBySub/linkSub

Recommended regression test: Real signed ID token with wrong iss must be rejected. Separate identity test: same sub under different issuers must not resolve to the old uid.

7. Attacker uses an expired ID token

Outcome: Expected to be blocked by jsonwebtoken exp validation, but required exp/iat presence is not enforced explicitly and real-JWT expired-token coverage is incomplete.

Affected: lib/oidc.js verifyIdToken

Recommended regression test: Real signed ID token with exp in the past must be rejected; token with missing exp/iat should also be rejected after adding explicit required-claim checks.

8. Attacker uses alg=none token

Outcome: Blocked. getSigningKey rejects algorithms outside RS*/ES* before key selection; alg=none is not in SUPPORTED_SIGNING_ALGORITHMS. Regression coverage is indirect and should use a real unsigned token.

Affected: lib/oidc.js getSigningKey

Recommended regression test: Unsigned alg=none ID token is rejected and does not call success.

9. Attacker rotates kid / unknown kid

Outcome: Unknown kid is rejected because getSigningKey filters JWKS candidates by kid and throws when no key matches. Authentik signing-key rotation may fail temporarily because JWKS is cached for one hour and there is no retry-on-unknown-kid refresh path.

Affected: lib/oidc.js getJwks/getSigningKey

Recommended regression test: Token with unknown kid must trigger a JWKS refresh once, then accept if the refreshed JWKS contains the new key; still reject if refreshed JWKS lacks it.

10. Attacker registers email equal to existing NodeBB admin

Outcome: Unsafe under current defaults if Authentik returns email_verified true. The plugin automatically links a new OIDC subject to an existing NodeBB account by verified email, including privileged accounts. This is already recorded as High.

Affected: lib/identity.js resolve/linkSub

Recommended regression test: Existing local admin with admin@example.com and no authentikSub; new OIDC subject with admin@example.com must not return admin uid unless explicit trusted-email-linking policy is enabled and privileged-account safeguards pass.

11. Attacker manipulates group claim to become admin

Outcome: Blocked currently because group/role mapping is not implemented and normalizeClaims drops group/role claims.

Affected: lib/oidc.js normalizeClaims, lib/sync.js

Recommended regression test: ID token/UserInfo with groups ["admin"] does not add NodeBB groups or admin privileges.

12. Attacker creates group named "not-admin"

Outcome: Blocked currently because group/role mapping is not implemented. Future group mapping must use exact matching, not substring matching.

Affected: future group sync only

Recommended regression test: When group mapping is implemented, group "not-admin" must not match configured admin group "admin".

13. Authentik user email changes

Outcome: Partially safe. Existing linked sub continues resolving by sub. If the changed email belongs to another NodeBB uid, resolveExistingSub rejects. If the changed email is unverified and does not belong to another uid, existing sub still logs in and updates authentikLastEmail to the unverified changed email, while not changing the NodeBB account email. This may be acceptable as profile metadata, but should be policy-reviewed.

Affected: lib/identity.js resolveExistingSub

Recommended regression test: Linked sub changes to verified email owned by another uid -> reject. Linked sub changes to new verified email -> login succeeds but NodeBB email is not changed unless explicit verified-email sync is enabled.

14. Authentik user is removed from admin group

Outcome: Not applicable currently. No group/admin mapping exists, so removal has no effect. If future mapping grants NodeBB admin/moderator roles, removal/revocation behavior must be explicit and tested.

Affected: future group sync only

Recommended regression test: Future configured admin mapping removes NodeBB admin/group membership on next login or scheduled sync when Authentik group is absent, if that is the configured ownership policy.

15. NodeBB user is banned locally

Outcome: Unsafe gap. The plugin does not check banned/suspended/deleted account state before strategy.success. This is already recorded as High.

Affected: lib/identity.js resolve, lib/strategy.js success path

Recommended regression test: Banned/suspended user with linked sub is rejected; banned/suspended local account with matching verified email is not linked.

16. Token endpoint is down

Outcome: Fails closed. exchangeCode uses server-to-server requestJson with timeout; thrown errors go to strategy.error and do not call success. Logging/error sanitization still needs hardening so token endpoint errors cannot leak sensitive request details.

Affected: lib/oidc.js exchangeCode, lib/http.js requestJson, lib/strategy.js catch

Recommended regression test: exchangeCode throws timeout/HTTP 500; assert no session success, diagnostics are sanitized, and no code/client_secret/token values appear in logs.

17. JWKS endpoint is down

Outcome: Fails closed for uncached keys because getJwks/requestJson throws and ID-token verification fails. If a cached JWKS exists and is still within one hour, verification can continue using cached public keys.

Affected: lib/oidc.js getJwks/getSigningKey

Recommended regression test: Empty cache + JWKS failure -> login rejected. Warm cache + JWKS failure + token signed by cached key -> login accepted if token otherwise valid.

18. Authentik rotates signing keys

Outcome: Partially handled. Tokens signed by old cached keys continue until cache expiry. Tokens signed by a new kid can fail until the one-hour JWKS cache expires because unknown kid does not trigger immediate JWKS refresh.

Affected: lib/oidc.js jwksCache/getSigningKey

Recommended regression test: Cached JWKS lacks new kid; token with new kid should refresh JWKS once and then validate if the provider now publishes the new key.

19. Two login flows happen in parallel in same browser

Outcome: Mostly safe. req.session.authentikOidc stores entries keyed by state and keeps up to five entries, so simultaneous login attempts should not overwrite each other when states differ. Gaps remain because stateStore.create can accept caller-supplied fixed state and tests do not explicitly prove two simultaneous attempts are isolated.

Affected: lib/state.js create/consume

Recommended regression test: Create two login starts in same session, consume the second then first, assert each returns its own nonce/codeVerifier and consuming one does not delete the other.

20. NodeBB runs behind reverse proxy with unusual Host/X-Forwarded headers

Outcome: Mostly safe if nconf url is configured correctly. Callback/login/back-channel URLs use configured NodeBB URL, not Host/X-Forwarded headers. Register redirect "next" accepts only safe relative paths from query/header. If nconf url itself is wrong, redirect_uri will be wrong.

Affected: lib/config.js getCallbackUrl/getLoginUrl/getBackchannelLogoutUrl, lib/routing.js safeRelativeNext

Recommended regression test: Behind-proxy request with Host/X-Forwarded-Host set to attacker values still produces configured public redirect_uri and login URL. Separate config test should fail when nconf url is missing or not HTTPS outside explicit local development.

----

## Final ship-gate checklist - 2026-05-09

The plugin cannot ship unless every item below is checked.

- [x] Authorization Code Flow only
- [ ] PKCE S256 enabled
  - Needs fixing: PKCE exists and uses S256, but it can be disabled through admin settings.
- [ ] state generated, stored, verified, consumed
  - Needs fixing: state is stored and consumed in session, but state generation can accept caller-provided state and cross-session/concurrent regression coverage is incomplete.
- [x] nonce generated and validated if ID token is used
- [ ] iss validated exactly
  - Needs fixing: ID-token verification uses exact configured issuer, but discovery accepts trailing-slash issuer differences and identity mappings are not issuer-qualified.
- [x] aud/client_id validated
- [ ] exp validated
  - Needs fixing: jsonwebtoken validates exp when present, but the plugin does not explicitly require exp/iat presence.
- [x] signature validated via trusted JWKS
- [x] alg allowlist enforced
- [x] redirect_uri fixed/allowlisted
- [ ] no open redirect after login/logout
  - Needs fixing: current login/register redirects are constrained, but logout/session-clear return-target and evil.com regression coverage remains incomplete.
- [ ] identity key is issuer + sub, not email alone
  - Needs fixing: mapping keys are sub-only and verified-email linking is automatic.
- [x] email_verified considered before email-based linking
- [ ] no silent takeover of existing NodeBB accounts
  - Needs fixing: verified-email login can silently link to existing local accounts, including admin accounts.
- [ ] no token/client_secret leakage in logs
  - Needs fixing: no direct token/client_secret logs were found, but raw upstream error messages/stacks and shallow metadata redaction can leak secrets.
- [ ] session regenerated after login
  - Needs fixing: NodeBB strategy flow likely handles session creation, but plugin-specific verification/regression coverage for session regeneration/fixation is missing.
- [x] role/group mapping exact and least-privilege
  - Current status: no role/group mapping exists, so Authentik group claims grant no privileges.
- [ ] banned/suspended users cannot bypass via SSO
  - Needs fixing: plugin does not check NodeBB banned/suspended/deleted state before SSO success.
- [ ] all auth state works in clustered NodeBB deployments
  - Needs fixing: OIDC state is in req.session rather than process memory, but clustered shared-session requirements are not documented/tested and DB link locks can get stuck after worker crash.
- [ ] tests cover negative auth cases
  - Needs fixing: many negative cases exist, but required real-JWT and strategy-level negative tests remain incomplete.
