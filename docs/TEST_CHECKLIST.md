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
- `sub` mapped to uid A but email belongs to uid B rejects.
- Missing email rejects.
- String `"true"` for `email_verified` rejects.

## Manual Authentik Integration

1. Create an Authentik OAuth2/OIDC provider using authorization code flow.
2. Set redirect URI to the callback URL shown in the NodeBB ACP.
3. Enable the plugin and fill issuer, client id, client secret, scopes, endpoints, and JWKS URI.
4. Use discovery from issuer and confirm endpoints populate correctly.
5. Login with a new verified Authentik user.
6. Login again with the same Authentik user and confirm the same uid is used.
7. Create a local NodeBB account with the same verified email and confirm SSO links to it without duplicate creation.
8. Test an Authentik user with unverified email and confirm login is rejected.
9. Change the provider email after linking and confirm login still resolves by `sub`.
10. Create a deliberate sub/email collision and confirm login fails closed with a warning log.

## Live Test Requirements

- Rebuild and restart NodeBB after plugin code changes.
- Re-run ACP discovery and save settings after issuer-handling changes.
- Test in a clean/incognito browser so Authentik and NodeBB sessions do not hide account-selection behavior.
- Capture the Authentik `sub`, email, `email_verified`, and preferred username for each live test account.
- Confirm the NodeBB database has one mapping for the successful login: `authentik:sub:uid` contains the `sub` and the target user has `authentikSub`, `authentikIssuer`, `authentikLinkedAt`, and `authentikLastLoginAt`.
- Confirm repeated login with the same Authentik account returns to the same NodeBB uid and does not create another account.
- Confirm an Authentik email change after linking still logs into the originally linked NodeBB account by `sub`.
- Confirm an existing local NodeBB account with a verified matching email links without duplicate account creation.
- Confirm unverified or missing email claims fail closed and leave no new user or mapping behind.
- Confirm a deliberate `sub`/email collision fails closed and logs a warning.

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
