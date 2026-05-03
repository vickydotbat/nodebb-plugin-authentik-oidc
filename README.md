# nodebb-plugin-authentik-oidc

Authentik-compatible OAuth2/OIDC SSO for NodeBB with strict verified-email identity linking.

## Features

- Adds `/auth/authentik` and `/auth/authentik/callback` through NodeBB's SSO strategy flow.
- Uses OIDC `sub` as the permanent external identity.
- Links existing NodeBB users by email only when `email_verified === true`.
- Rejects missing/unverified email for unlinked identities.
- Rejects `sub`/email collisions instead of silently creating duplicate users.
- Keeps username display-only and never uses it for identity matching.
- Provides an ACP settings page with issuer discovery and secret-preserving saves.

Planned profile synchronization work is tracked in [Next steps](docs/NEXT_STEPS.md). Authentik profile data such as username, email, display name, and avatar should be synced only through explicit admin settings after identity resolution succeeds.

Planned ACP improvements include grouped settings, sync toggles, authorization-parameter controls, diagnostics, mapping audit/repair tools, and dry-run profile synchronization.

Planned user-profile controls include linked-account status, managed-field indicators, safe profile refresh, optional disconnect policy, and redirects to configured Authentik self-service pages.

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

## Operational Notes

NodeBB can only enforce identity rules after Authentik returns OIDC claims. Configure Authentik enrollment flows to reject missing email, duplicate emails, and duplicate usernames before provider-side account creation completes.

If testing unverified email behavior, inspect the actual OIDC ID token or userinfo response. Authentik custom attributes do not necessarily change the emitted `email_verified` claim.

## Tests

```bash
npm test
```

Additional planning and operating notes:

- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Security notes](docs/SECURITY.md)
- [Test checklist](docs/TEST_CHECKLIST.md)
- [Next steps](docs/NEXT_STEPS.md)
