# nodebb-plugin-authentik-oidc

Authentik-compatible OAuth2/OIDC SSO for NodeBB with strict verified-email identity linking.

## Features

- Adds `/auth/authentik` and `/auth/authentik/callback` through NodeBB's SSO strategy flow.
- Uses OIDC `sub` as the permanent external identity.
- Links existing NodeBB users by email only when `email_verified === true`.
- Rejects missing/unverified email for unlinked identities.
- Rejects `sub`/email collisions instead of silently creating duplicate users.
- Keeps username display-only and never uses it for identity matching.
- Provides an ACP settings page with issuer discovery, secret-preserving saves, authorization parameters, username collision policy, sanitized last-failure diagnostics, mapping audit, and stale mapping repair.
- Provides a read-only user account page for linked Authentik/OIDC status and optional Authentik self-service links without exposing OIDC subjects or mapping keys.

Planned profile and role/group synchronization work is tracked in [Next steps](docs/NEXT_STEPS.md). Authentik profile data such as username, email, display name, avatar, groups, and roles should be synced only through explicit admin settings after identity resolution succeeds.

Planned ACP improvements include grouped settings, sync toggles, authorization-parameter controls, broader diagnostics, and dry-run profile synchronization.

User-profile controls are currently read-only. Safe profile refresh and disconnect policies are intentionally deferred until the login flow can constrain those actions to the already linked OIDC `sub`.

## Install During Development

From this plugin directory:

```bash
npm install
npm link
```

From the NodeBB directory:

```bash
npm link nodebb-plugin-authentik-oidc
./nodebb build
./nodebb start
```

Activate the plugin in the NodeBB ACP, restart NodeBB, then configure it at:

```text
/admin/plugins/authentik-oidc
```

## Authentik Setup

Create an Authentik OAuth2/OpenID provider:

- Flow: authorization code
- Client type: confidential
- Redirect URI: the callback URL shown in the plugin ACP page
- Scopes: `openid email profile`

Use the issuer URL from Authentik in the plugin settings and click Discover to populate endpoints.

Optional provider authorization parameters can be configured as a query string, for example:

```text
prompt=login
```

Use this when testing account selection or when an existing Authentik browser session is causing the wrong account to be reused. The plugin rejects attempts to override protocol-critical parameters such as `state`, `nonce`, `client_id`, `redirect_uri`, and `scope`.

## Operational Notes

NodeBB can only enforce identity rules after Authentik returns OIDC claims. Configure Authentik enrollment flows to reject missing email, duplicate emails, and duplicate usernames before provider-side account creation completes.

If testing unverified email behavior, inspect the actual OIDC ID token or userinfo response. Authentik custom attributes do not necessarily change the emitted `email_verified` claim.

Use Identity Mapping Diagnostics in the ACP to audit `authentik:sub:uid` mappings. The repair action only removes stale subject mappings that point to missing NodeBB users and requires confirmation.

Use Last failure in the ACP diagnostics section when an OIDC callback is rejected. It stores only sanitized metadata such as rejection code, claim presence, `email_verified` type/value, issuer metadata, and whether userinfo was used. It does not store raw tokens, authorization codes, full claim payloads, or email addresses.

Provider URLs and self-service links must be HTTPS by default and cannot target localhost or private network addresses. The loopback HTTP exception is only for explicit local development.

The username collision policy defaults to creating a safe unique NodeBB username for new SSO users. Set it to reject if new SSO account creation should fail when the provider's display username conflicts with an existing NodeBB username/userslug.

Optional Authentik self-service URLs can be configured in the ACP. When set, linked users see those external profile, password, MFA, and session-management links on `/user/<userslug>/authentik-oidc`.

## Tests

```bash
npm test
```

Additional planning and operating notes:

- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Security notes](docs/SECURITY.md)
- [Test checklist](docs/TEST_CHECKLIST.md)
- [Next steps](docs/NEXT_STEPS.md)
