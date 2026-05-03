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

## Manual Observations

- 2026-05-03: In a browser already logged in as the existing NodeBB account `archvillainette`, starting Authentik login after verifying that account's email showed the existing account avatar before failing later in the OIDC callback. Keep this as a regression check: a verified-email match may link even when the Authentik username/display name differs, but it must not use username for identity and must still fail closed on issuer or `sub`/email conflicts.
