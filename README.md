# nodebb-plugin-authentik-oidc

Authentik-compatible OAuth2/OIDC SSO for NodeBB with strict verified-email identity linking.

## Features

- Adds `/auth/authentik` and `/auth/authentik/callback` through NodeBB's SSO strategy flow.
- Uses OIDC `sub` as the permanent external identity.
- Links existing NodeBB users by email only when `email_verified === true`.
- Rejects missing/unverified email for unlinked identities.
- Rejects `sub`/email collisions instead of silently creating duplicate users.
- Keeps username display-only and never uses it for identity matching.
- Can run in link-only mode by disabling new SSO account creation while still allowing verified-email links to existing NodeBB users.
- Provides an ACP settings page with issuer discovery, secret-preserving saves, authorization parameters, username collision policy, sanitized last-failure diagnostics, mapping audit, and stale mapping repair.
- Provides a read-only user account page for linked Authentik/OIDC status and optional Authentik self-service links without exposing OIDC subjects or mapping keys.
- Supports optional OIDC back-channel logout so Authentik session closure can revoke NodeBB sessions.
- Supports opt-in display name synchronization from the OIDC `name` claim after identity resolution succeeds.

Planned profile and role/group synchronization work is tracked in [Next steps](docs/NEXT_STEPS.md). Authentik profile data such as username, email, avatar, groups, and roles should be synced only through explicit admin settings after identity resolution succeeds. Display name sync is available as a conservative opt-in setting.

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
- Optional single logout: enable OIDC back-channel logout and set Authentik's back-channel logout URI to the URL shown in the plugin ACP page

Use the issuer URL from Authentik in the plugin settings and click Discover to populate endpoints. For Authentik-side enrollment, email-verification, duplicate-account, account-selection, and logout guidance, see [Authentik setup and enrollment hardening](docs/AUTHENTIK_SETUP.md).

Optional provider authorization parameters can be configured as a query string, for example:

```text
prompt=login
```

By default, the plugin sends `prompt=login` and `max_age=0` so Authentik enrollment and linking screens do not silently reuse another Authentik browser session. This avoids confusing account-selection screens where a new enrollment can show the avatar for an already-authenticated Authentik account. Disable "Force fresh Authentik login" only if your Authentik flow already makes account selection explicit. The plugin rejects attempts to override protocol-critical parameters such as `state`, `nonce`, `client_id`, `redirect_uri`, and `scope`.

If Authentik still shows a previous user's current-session card or avatar during new enrollment, enable "Clear Authentik session before login" and populate the end-session endpoint from discovery. Add `https://your-forum.example.com/auth/authentik?authentikFreshLogin=1` as an allowed post-logout redirect URI in Authentik if your provider requires explicit post-logout redirect registration.

## Operational Notes

NodeBB can only enforce identity rules after Authentik returns OIDC claims. Configure Authentik enrollment flows to reject missing email, duplicate emails, and duplicate usernames before provider-side account creation completes.

Authentik 2025.10 and newer default the standard email scope's `email_verified` claim to `false`; older Authentik releases may have emitted `true` by default. Use an explicit Authentik email scope mapping that reflects your real verification state, then confirm the actual ID token or userinfo response contains the expected boolean value.

If testing unverified email behavior, inspect the actual OIDC ID token or userinfo response. Authentik custom attributes do not necessarily change the emitted `email_verified` claim.

Use Identity Mapping Diagnostics in the ACP to audit subject mappings. The plugin writes both the auditable `authentik:sub:uid` object mapping and the direct `authentik:sub:<sub>` lookup key for compatibility; the repair action only removes stale subject mappings that point to missing NodeBB users and requires confirmation.

Use Last failure in the ACP diagnostics section when an OIDC callback is rejected. It stores only sanitized metadata such as rejection code, claim presence, `email_verified` type/value, issuer metadata, and whether userinfo was used. It does not store raw tokens, authorization codes, full claim payloads, or email addresses.

Provider URLs and self-service links must be HTTPS by default and cannot target localhost or private network addresses. The loopback HTTP exception is only for explicit local development.

The username collision policy defaults to creating a safe unique NodeBB username for new SSO users. Set it to reject if new SSO account creation should fail when the provider's display username conflicts with an existing NodeBB username/userslug.

Disable new SSO account creation when the forum should accept only users who already have a linked Authentik subject or an existing NodeBB account with the same verified email. This does not weaken verified-email linking; it only blocks brand-new NodeBB user creation.

Optional Authentik self-service URLs can be configured in the ACP. When set, linked users see those external profile, password, MFA, and session-management links on `/user/<userslug>/authentik-oidc`.

Closing sessions from Authentik requires Authentik Single Logout to be configured. Enable OIDC back-channel logout in this plugin's ACP page, configure the displayed back-channel logout URL as the Authentik provider's Logout URI, set Logout Method to Back-channel, and ensure Authentik can reach the NodeBB public URL. The plugin validates the signed logout token and revokes NodeBB sessions for the linked `sub` or stored OIDC `sid`.

Back-channel logout is triggered only when Authentik terminates the user session and identifies an active OIDC provider session for NodeBB. Revoking consent for the NodeBB application is not a logout signal by itself. If deleting an Authentik session does not log the user out of NodeBB, open the plugin ACP diagnostics and click Last logout:

- No record: Authentik did not POST to NodeBB, or the request did not reach NodeBB.
- `outcome: rejected`: Authentik called NodeBB, but logout-token validation failed. Check issuer, client id/audience, JWKS URI, and signing key support.
- `outcome: unmatched`: the logout token was valid, but its `sub`/`sid` did not match a stored NodeBB mapping. Log into NodeBB through Authentik again, then retry.
- `outcome: revoked`: NodeBB revoked all sessions for the mapped uid. Refresh the browser or try a protected action to confirm the old session is gone.

After changing Authentik logout settings, log out of NodeBB and log back in through Authentik once so Authentik and the plugin both have a fresh provider-session record.

Display name synchronization is disabled by default. When enabled, successful SSO logins update NodeBB `fullname` from the provider's OIDC `name` claim after the account has already been resolved by `sub` or verified email. Missing `name` claims do not blank the local field.

## Tests

```bash
npm test
```

Additional planning and operating notes:

- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Security notes](docs/SECURITY.md)
- [Test checklist](docs/TEST_CHECKLIST.md)
- [Next steps](docs/NEXT_STEPS.md)
