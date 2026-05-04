# Test Checklist

## Automated

- `npm test`

Covered baseline cases:

- New verified OIDC user creates exactly one NodeBB user.
- Same `sub` repeatedly resolves to the same uid.
- Existing NodeBB user with same verified email links without duplicate creation.
- Unverified email rejects without creating or linking.
- Username conflict produces a unique username.
- Existing `sub` with changed email still resolves by sub.
- Existing `sub` with changed unverified email still resolves by sub without using that email to link or create an account.
- `sub` mapped to uid A but email belongs to uid B rejects, even when the emitted email is unverified.
- Missing email rejects.
- String `"true"` for `email_verified` rejects.
- Optional display name sync updates `fullname` only after successful identity resolution and does not blank it when `name` is missing.
- Mapping audit reports healthy, stale, missing reverse, conflicting reverse, and duplicate user-side subject links.
- Stale mapping repair requires explicit confirmation and removes only mappings whose uid no longer exists.
- Authorization parameters are appended to the provider redirect while plugin-controlled OIDC parameters cannot be overridden.
- Username collision reject policy fails closed without creating a user or mapping.
- Disabling new SSO account creation rejects brand-new verified users without creating a user or mapping, while verified-email linking to an existing account still works.
- Last failure diagnostics store sanitized claim metadata without raw tokens or email addresses.
- Last authorization diagnostics preserve a sanitized provider-relative clear-session return target and do not store state or nonce.
- JWKS diagnostics report only sanitized signing-key metadata and fail when no supported signing key exists.
- Authentik self-service URLs are trimmed, saved, and validated as optional HTTPS settings.
- Provider URL validation rejects localhost/private network targets by default.
- User linked-account state exposes safe metadata without the OIDC subject or mapping keys.
- The profile menu link is self-only.
- OIDC state is generated when missing, required on callback, and single-use.
- ID token validation rejects unsupported algorithms and ignores non-signing JWKS keys.
- Back-channel logout setting saves and exposes a computed logout URL.
- OIDC logout token validation requires the back-channel logout event and rejects nonce.
- Back-channel logout revokes NodeBB sessions for mapped `sub` or stored `sid` only when enabled.
- Back-channel logout accepts Authentik-style form-encoded `logout_token` request bodies.
- Back-channel logout diagnostics record sanitized `revoked` and `unmatched` outcomes without storing raw logout tokens.

## Manual Authentik Integration

1. Create an Authentik OAuth2/OIDC provider using authorization code flow.
2. Set redirect URI to the callback URL shown in the NodeBB ACP.
3. Enable the plugin and fill issuer, client id, client secret, scopes, endpoints, and JWKS URI.
4. Use discovery from issuer and confirm endpoints populate correctly.
5. Configure Authentik email scope mapping so `email_verified` reflects the intended verification state.
6. Configure Authentik enrollment policies for required email and the desired duplicate email/username rejection behavior.
7. Login with a new verified Authentik user.
8. Login again with the same Authentik user and confirm the same uid is used.
9. Create a local NodeBB account with the same verified email and confirm SSO links to it without duplicate creation.
10. Test an Authentik user with unverified email and confirm the actual OIDC claim is boolean `false` and login is rejected.
11. Change the provider email after linking and confirm login still resolves by `sub`.
12. Create a deliberate sub/email collision and confirm login fails closed with a warning log.
13. Disable new SSO account creation and confirm a brand-new verified Authentik user is rejected without a NodeBB user or mapping.
14. With new SSO account creation still disabled, confirm an existing NodeBB account with the same verified email links successfully.

## Manual Back-Channel Logout

Back-channel logout requires configuration in both systems. The NodeBB ACP toggle only tells the plugin to accept and process logout tokens; it does not make Authentik send them.

1. Rebuild and restart NodeBB after installing the plugin version that contains `/auth/authentik/backchannel-logout`.
2. In NodeBB ACP, enable OIDC back-channel logout and save settings.
3. Copy the displayed back-channel logout URL.
4. In the Authentik OAuth2/OIDC provider used by NodeBB, set the provider's back-channel logout URI to that exact URL.
5. In the same Authentik provider, set Logout Method to Back-channel and save the provider.
6. Confirm the URL is publicly reachable by Authentik over HTTPS and is not blocked by a reverse proxy, firewall, Cloudflare rule, or private-network routing.
7. Confirm the Authentik version supports OIDC back-channel logout and Single Logout for OAuth2/OIDC providers.
8. Confirm the NodeBB application login is using this exact Authentik provider, not another provider with a similar name.
9. Confirm the NodeBB OIDC settings include the same issuer and JWKS URI used to validate login ID tokens.
10. Log out of NodeBB and log back in through Authentik so Authentik creates a fresh active OIDC provider session and the plugin stores the current OIDC `sub` and, when emitted, `sid` mapping.
11. Terminate the Authentik user session. Prefer an actual user logout through Authentik's logout flow first, then test administrative session deletion. Revoking consent for the NodeBB application is not sufficient by itself.
12. Confirm Authentik sends a POST request containing `logout_token` to `/auth/authentik/backchannel-logout`.
13. Confirm NodeBB responds `204` and logs `revoked NodeBB sessions from OIDC back-channel logout`.
14. In the NodeBB plugin ACP, click Last logout and record the sanitized outcome.
15. Refresh the existing NodeBB browser tab and confirm the user is no longer authenticated.
16. If NodeBB still shows the user as logged in, check whether the browser page is only displaying cached content by navigating to a protected action or reloading with cache disabled.

Troubleshooting:

- No request reaches NodeBB: the Authentik provider is missing the back-channel logout URI, Authentik was not restarted/saved, or the NodeBB URL is unreachable from Authentik.
- NodeBB returns `400`: inspect NodeBB logs for logout-token validation failure, issuer/audience mismatch, missing JWKS URI, unsupported signing key, missing back-channel logout event, or invalid nonce.
- NodeBB returns `204` but no revocation happens: the logout token `sub` or `sid` did not match a stored NodeBB mapping. Re-login through NodeBB SSO and retry.
- NodeBB logs revocation but the browser appears logged in: refresh the page, try a protected action, and confirm NodeBB's session store actually removed the session for the uid.
- ACP Last logout shows no record: Authentik did not call the plugin route at all.
- ACP Last logout shows `unmatched`: Authentik called the plugin with a valid token, but the token did not map to the linked NodeBB user.

## Live Test Requirements

- Rebuild and restart NodeBB after plugin code changes.
- Re-run ACP discovery and save settings after issuer-handling changes.
- Test in both a clean/incognito browser and a browser with an active different Authentik/NodeBB session so session-contamination behavior is visible.
- For brand-new Authentik enrollment with no verified-email match, confirm Authentik does not show another user's NodeBB avatar/current-session profile and NodeBB creates a clean user only after verified claims resolve safely.
- For verified-email linking to an existing NodeBB account, confirm preserving/showing that existing NodeBB account's avatar is acceptable and that the resolved uid is exactly the account whose verified email matched.
- Use ACP Last authorization after each session-contamination test and record whether the plugin used direct authorization, OIDC end-session, or an Authentik invalidation/logout flow override.
- When using an Authentik invalidation/logout flow override with `next`, confirm Last authorization shows `returnTo` as a provider-relative `/application/o/authorize/...` URL with state and nonce removed.
- Capture the Authentik `sub`, email, `email_verified`, and preferred username for each live test account.
- Confirm the NodeBB database has subject mappings for the successful login: `authentik:sub:uid` contains the `sub`, the direct `authentik:sub:<sub>` key points to the same uid, and the target user has `authentikSub`, `authentikIssuer`, `authentikLinkedAt`, and `authentikLastLoginAt`.
- Confirm repeated login with the same Authentik account returns to the same NodeBB uid and does not create another account.
- Confirm an Authentik email change after linking still logs into the originally linked NodeBB account by `sub`.
- Confirm an existing local NodeBB account with a verified matching email links without duplicate account creation.
- Confirm unverified or missing email claims fail closed and leave no new user or mapping behind.
- Confirm a deliberate `sub`/email collision fails closed and logs a warning.
- In ACP, run Identity Mapping Diagnostics and confirm the audit summary matches the database.
- If stale mappings exist, use Repair stale and confirm only mappings pointing to missing NodeBB users are removed.
- Use Last failure after a rejected callback and confirm it shows only sanitized metadata needed to inspect `email_verified` behavior.
- Test optional authorization parameters such as `prompt=login` or `prompt=select_account` if Authentik session reuse causes account-selection confusion.
- Configure Authentik self-service profile, password, MFA, and session URLs in the ACP and confirm `/user/<userslug>/authentik-oidc` shows only those external actions for the signed-in linked user.
- Confirm the linked-account page does not display the OIDC `sub`, raw claims, tokens, or database mapping keys.
- Complete the Manual Back-Channel Logout section above and record whether Authentik sent the logout token, how NodeBB responded, and whether the existing browser session was actually revoked.

## Manual Observations

- 2026-05-03: In a browser already logged in as the existing NodeBB account `archvillainette`, starting Authentik login after verifying that account's email showed the existing account avatar before failing later in the OIDC callback. Keep this as a regression check: a verified-email match may link even when the Authentik username/display name differs, but it must not use username for identity and must still fail closed on issuer or `sub`/email conflicts.
- 2026-05-03: Live login succeeded after preserving Authentik's exact discovered issuer for ID token validation. The successful login used the Authentik account that had previously been attempted during registration testing.
- 2026-05-03: Repeated live login with Authentik subject `87d50bc3c5d2632c233da129a87849b7a205479ae71df857321a2e2bf854fe94` resolved to the same NodeBB uid `28`.
- 2026-05-03: MongoDB mapping confirmed: `authentik:sub:uid` maps the subject to uid `28`, and `user:28` has `authentikSub`, `authentikIssuer` set to `https://auth.westgate.pw/application/o/nodebb/`, `authentikLinkedAt`, and `authentikLastLoginAt`.
- 2026-05-03: After changing the Authentik account email, login still resolved to the same NodeBB account by `sub`.
- 2026-05-03: Verified-email linking failed for existing account `archvillainette` and created `archvillainette-1`. Likely cause was the existing NodeBB email being present on the user object but absent from NodeBB's confirmed `email:uid` index. Added fallback lookup over existing user email fields before account creation, plus tests for unindexed matching email and ambiguous duplicate unindexed emails.
- 2026-05-03: After deleting duplicate account `archvillainette-1`, login failed with `OIDC subject maps to a missing NodeBB account` because `authentik:sub:uid` still pointed to the deleted uid. Added stale-sub cleanup so missing mapped users are logged, the stale mapping is removed, and verified-email linking can continue.
- 2026-05-03: Existing account `archvillainette` was successfully linked after stale mapping cleanup and unindexed-email fallback; no duplicate account was generated.
- 2026-05-03: Authentik-only user `TestVicky4` hit `Username already taken` during NodeBB account creation. Added create-time username retry handling because NodeBB rejects by slug/creation validation, not only exact username lookup.
- 2026-05-03: Registering through Authentik with a new username `TestVicky5` but an email already linked to a different Authentik subject allowed Authentik email verification to complete, then NodeBB rejected with `Existing account is linked to a different OIDC subject`. This is correct fail-closed plugin behavior after the provider returns claims; preventing the Authentik-side verification step requires Authentik flow/policy configuration.
- 2026-05-03: Existing NodeBB-only user `TestVicky6` plus Authentik registration using the same username but different email created a new NodeBB user named `TestVicky6 0`. This is safe from an identity-takeover perspective because username is not used for identity, but product behavior may need a stricter policy option to block new SSO account creation when `preferred_username` collides with an existing NodeBB username.
- 2026-05-03: During the `TestVicky6` flow, the Authentik UI showed the original `archvillainette` avatar before email verification. Treat as a top-priority session/profile contamination issue, not a cosmetic bug. It may indicate backend/account-selection context confusion and can undermine user trust or create an account-misdirection attack surface.
- 2026-05-03: Setting Authentik custom attributes to `email_verified: false` did not cause NodeBB rejection; login passed and NodeBB marked the email verified. This likely means Authentik still emitted OIDC `email_verified: true` or did not map the custom attribute into the actual claim. Add claim-inspection tooling or Authentik claim policy validation before considering the unverified-email live test passed.
- 2026-05-03: Authentik user with no email was rejected by NodeBB with `OIDC email is required`; no NodeBB user was created.
- 2026-05-03: Repeat login for linked `archvillainette` did not create a new NodeBB account. The browser appeared to hang after provider flows, but the NodeBB session was established successfully.
- 2026-05-03: Normal NodeBB password login still works.
- 2026-05-04: A test enrollment account whose email was not verified in time became locked out on the Authentik side. The account remained present as inactive, could not log in, could not complete email verification, and blocked re-registration with the same username because the username was already taken. Treat expired/unverified Authentik enrollment users as provider-side cleanup debt unless Authentik flow policy deletes, reactivates, or re-sends verification for them.
- 2026-05-04: `Clear Authentik session before login` with the discovered OIDC end-session endpoint reached Authentik's enrollment flow instead of clearing the displayed current-session avatar. ACP Last authorization showed `stage: provider-session-clear`, `clearProviderSessionBeforeLogin: true`, and redirect target `.../application/o/nodebb/end-session/?post_logout_redirect_uri=...`.
- 2026-05-04: Switching to `Session clear endpoint override = https://auth.westgate.pw/if/flow/default-invalidation-flow/` and return parameter `next` still landed on Authentik enrollment with URL `https://auth.westgate.pw/if/flow/enrollment/?next=%2F&flow_token=...` and still displayed another user's avatar. This suggests Authentik rewrote the intended `next` target to `/` or the invalidation flow did not clear the browser session before enrollment rendered.

## Open Live Items

- P0: Resolve session/avatar contamination. Confirm the only case where an existing NodeBB avatar appears during Authentik login/enrollment is when verified-email linking resolves to that exact existing NodeBB uid.
- Retest username collision in both ACP policies: "create a safe unique username" and "reject new SSO account creation".
- Capture actual OIDC ID token/userinfo claims for the `email_verified: false` scenario. Do not rely on Authentik custom attributes alone.
- Investigate Authentik account-selection/avatar behavior with the clear-session invalidation-flow override. Capture ACP Last authorization, browser redirect chain, Authentik flow slug, displayed user/avatar, final OIDC `sub`, and resolved NodeBB uid.
- Inspect Authentik `default-invalidation-flow` and enrollment flow configuration. Confirm whether the logout stage actually clears the browser session, whether `next` is restricted/re-written to `/`, and whether the enrollment prompt intentionally displays current authenticated user context.
- Investigate post-callback hang after successful login and confirm whether the callback response/redirect chain completes cleanly.
- Add Authentik-side flow/policy rules to reject registration when username or email already exists in Authentik, and verify they stop registration before Authentik redirects back to NodeBB.
- Add an Authentik-side cleanup policy or admin runbook for inactive enrollment users whose email verification expires before completion, especially because they reserve usernames and may require manual deletion or recovery.
- Live-test the linked-account profile page after rebuilding NodeBB and confirm the self-only profile menu route renders under the active theme.
- Live-test NodeBB session revocation after upstream Authentik logout/session closure with Authentik back-channel logout enabled, including verification that Authentik POSTed a `logout_token` to NodeBB.
