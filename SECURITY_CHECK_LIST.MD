# Authentik OIDC Security Checklist

Last reconciled: 2026-05-09 against the uncommitted remediation changes and `SECURITY_FINDINGS.MD`.

Legend:

- [x] Verified fixed in the current uncommitted implementation and covered by focused tests where practical.
- [ ] Still open before release, or requires live/NodeBB integration validation.

## 1. Flow Selection

- [x] Authorization Code Flow only: authorization URLs set `response_type=code`; no implicit, password, hybrid, or token-fragment flow is implemented.
- [x] `openid` is required in configured scopes.
- [x] PKCE S256 is always generated and sent; the old `usePkce` setting is ignored/removed from saved settings.
- [x] Confidential client token endpoint authentication defaults to `client_secret_basic`.
- [x] `client_secret_post` remains available only as explicit configuration.
- [x] `offline_access` is rejected because refresh tokens are not needed or stored.
- [ ] Confirm with a real Authentik application that default scopes remain `openid email profile` and no refresh token is minted.

## 2. Authorization Request Construction

- [x] Every login attempt generates plugin-owned random `state`, `nonce`, and PKCE verifier.
- [x] Caller-supplied Passport/NodeBB `options.state` is ignored.
- [x] State, nonce, and PKCE verifier are stored in the browser session and consumed on callback.
- [x] Reused, missing, wrong, and foreign-session state fail closed in unit tests.
- [x] Concurrent login starts in the same session keep distinct state entries.
- [x] Query-controlled `authentikFreshLogin` no longer bypasses provider-session clearing; the bypass now requires a one-time server-side session marker.

## 3. Redirect URI Safety

- [x] Callback, login, and back-channel URLs are built from configured NodeBB public URL, not request `Host` or `X-Forwarded-Host`.
- [x] Callback and back-channel URLs are rendered read-only in ACP.
- [x] Callback HTTP development allowance is split from provider endpoint loopback development allowance.
- [x] Authentik setup docs tell operators to register the exact callback URI and avoid wildcards.
- [x] Regression coverage proves hostile `Host` and `X-Forwarded-Host` values cannot change `redirect_uri`.
- [x] Provider-session-clear ignores request redirect parameters (`next`, `returnTo`, `callback`, `redirect`, `post_logout_redirect_uri`) in evil.com regression coverage.

## 4. Callback Handling

- [x] Provider `error` callbacks fail without token exchange or session success.
- [x] Callback parsing requires single non-empty string `code` and `state` when either callback parameter is present.
- [x] Duplicate `code` and duplicate/non-string `state` are rejected before state consumption and token exchange.
- [x] State is consumed before token exchange, preventing replay.
- [x] Authorization code exchange is server-to-server only; code is not sent to frontend JavaScript or stored.
- [x] Token endpoint URL is revalidated immediately before code exchange.
- [x] Callback route invocations with neither `code` nor `state` fail closed instead of starting a new login.
- [x] Non-GET callback route requests fail before state consumption or token exchange.
- [x] Token-endpoint failure regression proves no session success and sanitized error logging.

## 5. Discovery and Issuer Validation

- [x] Discovery issuer comparison is exact string equality.
- [x] Discovered authorization, token, JWKS, UserInfo, and end-session endpoints are validated before metadata is returned to ACP.
- [x] Provider endpoints require HTTPS by default.
- [x] Loopback HTTP provider endpoints require the explicit dangerous development setting.
- [x] ID-token and logout-token verification require exact configured issuer.
- [x] Discovery still supports an admin POST body issuer for ACP usability, but route middleware tests cover logged-in/settings-admin enforcement and SSRF validation is shared with saved settings.

## 6. ID Token Validation

- [x] ID tokens are required for login.
- [x] Normal login ID-token signature, issuer, audience, nonce, token-hash, and code-hash validation are delegated to `openid-client` during `authorizationCodeGrant`.
- [x] Authorization-code grant checks pass `expectedState`, `expectedNonce`, required ID token, PKCE verifier, and fresh-login `maxAge: 0` to `openid-client`.
- [x] `jose` JWT verification rejects `alg=none` and symmetric algorithms in the remaining direct-verification path.
- [x] Direct custom ID-token verification was removed from the normal production surface.
- [x] `sub`, `exp`, and `iat` are explicitly required.
- [x] `iat` future/age bounds are enforced.
- [x] `auth_time` is required and bounded when fresh provider login is requested.
- [x] Optional `idTokenSigningAlg` pinning is passed into `openid-client` client metadata as `id_token_signed_response_alg`.
- [x] Default algorithm behavior is pinned to `RS256`; administrators can explicitly configure another supported asymmetric algorithm.
- [x] Real signed JWT/JWKS tests cover wrong issuer, wrong audience, unknown kid, unsigned token, and malformed logout-token shapes in the remaining back-channel logout verifier.
- [x] Normal callback handling consumes `openid-client` processed `tokenSet.claims()` instead of re-verifying ID tokens with custom code.
- [x] Direct JWT handling remains only for JWKS diagnostics and `jose` back-channel logout token validation where NodeBB session policy is plugin-specific.

## 7. Access Token and UserInfo Handling

- [x] Canonical identity is `issuer + sub`, not email.
- [x] UserInfo is called server-to-server only.
- [x] UserInfo endpoint is revalidated before sending bearer tokens.
- [x] UserInfo `sub` must match ID-token `sub`.
- [x] UserInfo retrieval uses `openid-client.fetchUserInfo` with the validated ID-token `sub` as the expected subject.
- [x] Conflicting UserInfo `email` or `email_verified` is rejected.
- [x] Missing email fails closed for unlinked identities.
- [x] Access tokens are not persisted or rendered.
- [x] Explicit precedence keeps signed ID-token `preferred_username` and `name` over conflicting UserInfo profile values.
- [x] `openid-client` custom `safeFetch` disables automatic redirects, validates redirect targets, and rejects provider redirects instead of following them.

## 8. Account Linking and Takeover Prevention

- [x] Default policy is `no_auto_link`; matching verified email does not silently bind a new OIDC subject to an existing local account.
- [x] If account creation is enabled, a new SSO account is created with collision-safe username handling.
- [x] If account creation is disabled, matching local email fails instead of auto-linking under the default policy.
- [x] Existing subject mappings are issuer-qualified with a SHA-256 key over `issuer + "\x1f" + sub`.
- [x] Legacy sub-only mappings are used only when the stored `authentikIssuer` exactly matches the configured issuer, then rewritten.
- [x] Stale mappings to missing users fail closed and are not silently reassigned by email.
- [x] Banned users are rejected through NodeBB `user.bans.canLoginIfBanned` when available.
- [x] OIDC login no longer confirms local NodeBB email as part of normal default linking.
- [x] Optional `trusted_email_auto_link` requires local email already confirmed, blocks admin/moderator/privileged targets, and is covered by tests.
- [x] No writable user account-link endpoint is shipped; if account continuity beyond trusted migration is required later, it must be added as a separate CSRF-protected logged-in flow.
- [x] Optional fullname/display-name sync skips reserved staff/system names for non-privileged users.
- [x] Restricted-user handling checks common suspended, disabled, deactivated, and deleted flags in addition to NodeBB ban policy.

## 9. Role and Group Mapping

- [x] Role/group sync is not implemented.
- [x] `groups`, `roles`, and arbitrary custom claims are ignored by normalized claims.
- [x] No Authentik claim currently grants NodeBB admin/moderator/group membership.
- [x] Defensive tests prove group/role claims are ignored by normalized claims while role sync remains unimplemented.
- [x] Future role/group sync guardrails are documented: exact configured claim matching, explicit admin opt-in, clear case policy, removal policy, and NodeBB group APIs only.

## 10. Session Creation and Fixation

- [x] Plugin does not manually set session cookies, write `req.session.uid`, or accept uid from request query/body.
- [x] Session creation is delegated to the official NodeBB/Passport SSO strategy flow.
- [x] OIDC state is stored in `req.session`, not process globals.
- [ ] Verify in a NodeBB 4.x route/integration harness that successful OIDC login regenerates the pre-login anonymous session id.
- [ ] Verify production session cookies are HttpOnly, Secure, and SameSite=Lax or a reviewed equivalent.
- [x] Forced attacker-state callback strategy test proves exchange is skipped and success is not called.

## 11. CSRF and Login CSRF

- [x] OAuth callback state protects against attacker-created callback state in another browser session.
- [x] Back-channel logout is POST-only and token-authenticated by signed logout token, not browser CSRF.
- [x] Public ACP JavaScript sends `x-csrf-token` on admin POSTs.
- [x] Admin mutation routes include explicit CSRF middleware when the target NodeBB middleware exposes one; ACP client sends `x-csrf-token`.
- [x] Unit route-registration tests verify admin mutation routes attach CSRF middleware when NodeBB exposes one; no-CSRF HTTP behavior remains part of live NodeBB validation.
- [x] Back-channel logout is documented as intentionally CSRF-exempt and limited to signed logout-token processing.

## 12. Logout Behavior

- [x] Local NodeBB logout remains independent from Authentik RP-initiated logout.
- [x] Back-channel logout token validation checks signature, issuer, audience, events, no nonce, sub/sid, `iat`, and `jti`.
- [x] Back-channel logout replay is rejected with DB-backed `jti` cache.
- [x] Logout subject lookup is issuer-qualified for `sub`.
- [x] `sid` mappings store `{ issuer, sub, uid, sessionId }`.
- [x] Logout with `sid` revokes only the mapped NodeBB session when `user.auth.revokeSession` and a session id are available.
- [x] Unknown sub/sid is harmless.
- [x] Real verifier-path logout-token tests reject unsigned, wrong-issuer, wrong-audience, and unknown-kid tokens.
- [x] Fallback behavior is documented and tested: sub-only logout or missing session-specific API revokes sessions for the uid.
- [x] RP-initiated logout remains out of scope; docs require fixed allowlisted `post_logout_redirect_uri` if it is implemented later.

## 13. Token Storage

- [x] Access tokens, refresh tokens, ID tokens, authorization codes, state, nonce, and PKCE verifiers are not persisted.
- [x] Refresh tokens are not requested because `offline_access` is rejected.
- [x] No browser localStorage/sessionStorage token storage exists.
- [x] ACP diagnostics store sanitized metadata, not raw token sets.
- [x] Regression tests prove token response material containing `access_token`, `refresh_token`, and `id_token` does not appear in diagnostics or logs; tokens are not passed to identity/user fields.

## 14. Logging and Error Handling

- [x] Central recursive redaction exists in `lib/redact.js`.
- [x] Logger metadata redaction is recursive and value-aware.
- [x] Diagnostics and admin error surfaces use sanitized error messages.
- [x] JWT-like strings, OAuth parameters, Authorization/Cookie headers, and nested secret-bearing metadata are redacted in tests.
- [x] Raw emails were removed from operational logs that previously logged duplicate/unverified email paths.
- [x] Redaction tests include full callback URLs, nested arrays, token endpoint response bodies, and Authentik-style JSON error payloads.
- [x] Logger sanitizes error strings and stack text through central redaction before writing.

## 15. Admin Configuration Safety

- [x] Client secret is masked in public/admin settings.
- [x] `AUTHENTIK_OIDC_CLIENT_SECRET` overrides DB settings for deployments that want secrets outside NodeBB settings storage.
- [x] Dangerous development controls are split and disabled by default.
- [x] No production "disable TLS validation" or "skip token validation" option exists.
- [x] Admin authorization parameters cannot override protocol-critical fields.
- [x] Client id, client secret, HTTPS issuer/provider endpoints, `openid` scope, and callback URL validation are covered by focused tests.
- [ ] If NodeBB exposes an encrypted secret store, move `clientSecret` there. Otherwise keep documenting DB-resident secret and backup risk.
- [x] Unit route-registration tests verify admin mutation routes include settings-admin and CSRF middleware when available; live HTTP CSRF behavior remains a NodeBB validation item.
- [x] ACP/docs text labels dangerous settings and trusted auto-linking constraints.

## 16. Dependency Audit

- [x] `openid-client` added as the OIDC protocol dependency and now owns discovery, authorization URL construction, state/nonce/PKCE primitives, code grant processing, ID-token validation, and UserInfo retrieval.
- [x] `jose` added as the JWT/JWKS dependency for back-channel logout token verification.
- [x] `ipaddr.js` added for IP parsing/range classification; custom numeric IPv4/IPv6 SSRF range parsing was removed.
- [x] `zod` added for settings normalization and cross-field validation; custom ad hoc settings coercion was replaced with a schema.
- [x] `jsonwebtoken` removed from runtime dependencies.
- [x] Node engine floor raised to `>=20.19.0`.
- [x] `package-lock.json` updated.
- [x] `npm audit --audit-level=low` reported 0 vulnerabilities in the current workspace.
- [ ] Add CI/release checks for `npm audit`, OSV/GitHub advisory review, and lockfile review.
- [x] Direct `jsonwebtoken` verification was removed; remaining logout-token JWT verification uses `jose`.
- [ ] Monitor `passport-strategy`; keep or replace depending on NodeBB 4.x recommended strategy base.

## 17. NodeBB Integration Points

- [x] Login/callback registration uses NodeBB auth strategy integration.
- [x] User creation uses NodeBB `user.create`.
- [x] Back-channel logout uses NodeBB user auth revocation APIs.
- [x] OIDC state uses NodeBB session storage and is cluster-safe when NodeBB sessions are shared.
- [ ] Verify against a real NodeBB 4.x install that auth init, callback route behavior, admin API CSRF, user creation, profile page, and back-channel logout work as expected.
- [ ] Verify `/register` interception route ordering and bypass behavior (`local=1`, invite tokens, registration disabled/invite-only, logged-in users).
- [x] DB link lock is timestamped and stale locks are reclaimed after a TTL while fresh concurrent locks still fail closed.
- [x] Clustered deployments are documented as requiring a shared NodeBB session store; no process-memory fallback is added.

## 18. Threat-Model Scenario Matrix

- [x] Login CSRF: session-bound state blocks foreign callback state.
- [x] Code injection: state plus always-on PKCE binds code to login session.
- [x] Host-header redirect poisoning: callback URL comes from configured NodeBB URL.
- [x] Callback replay: consumed state prevents normal replay.
- [x] ID token from another client: audience/azp checks reject.
- [x] ID token from another issuer: exact issuer verification rejects.
- [x] Expired ID token: JWT validation plus required `exp` reject.
- [x] `alg=none`: unsupported algorithm reject.
- [x] Unknown kid: no matching JWKS key rejects.
- [x] Existing local/admin email takeover under default policy: no default auto-link.
- [x] Group claim privilege escalation: claims ignored because role sync is absent.
- [x] Banned linked user: rejected when NodeBB ban API is available.
- [x] Token/JWKS endpoint down: fails closed.
- [x] Parallel login flows: distinct session state entries.
- [x] Real-JWT/JWKS threat tests cover critical ID-token and logout-token scenarios.
- [ ] Add NodeBB live/session threat tests for session fixation, route method handling, CSRF, and cookie attributes.
- [x] Key-rotation test covers unknown `kid` JWKS refresh.

## 19. Review Output Format

Future security reviews should continue to report findings in this table:

| Severity | Area | Finding | Exploit scenario | Evidence in code | Fix | Test |
| --- | --- | --- | --- | --- | --- | --- |

Each review should also include:

1. Top 5 fixes in priority order.
2. Security invariants that must never be broken.
3. Tests that should be added before release.
4. Code locations that need human review.
5. Things that could not be verified from code alone.

## 20. Minimum Release Gate

The plugin should not ship until every item below is checked.

- [x] Authorization Code Flow only
- [x] PKCE S256 enabled
- [x] state generated, stored, verified, consumed
- [x] nonce generated and validated
- [x] `iss` validated exactly
- [x] `aud`/client_id validated
- [x] `exp` required and validated
- [x] signature validated via trusted JWKS
- [x] alg allowlist enforced
- [x] redirect_uri fixed/allowlisted
- [x] no open redirect after login/logout has explicit evil.com regression coverage
- [x] identity key is issuer + sub, not email alone
- [x] email_verified considered before any email-based trusted linking
- [x] no silent takeover of existing NodeBB accounts under default policy
- [x] no known token/client_secret leakage in logs after recursive redaction
- [ ] session regenerated after login is verified in NodeBB 4.x
- [x] role/group mapping exact and least-privilege by absence of role sync
- [x] banned users cannot bypass via SSO when NodeBB ban API is available
- [x] suspended/disabled/deleted user handling is covered for common NodeBB fields and must be live-verified against the target NodeBB 4.x install
- [x] all auth state uses NodeBB sessions with documented shared-session requirement for clustered deployments
- [x] callback method behavior is unit-tested and admin POST routes attach explicit CSRF middleware when available; live NodeBB CSRF behavior remains a deployment validation item
- [x] `openid-client` custom fetch redirect/SSRF behavior is hardened and tested
- [x] real JWT/JWKS integration-style tests cover negative auth and logout cases
