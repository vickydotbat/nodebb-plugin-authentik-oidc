# nodebb-plugin-authentik-oidc

Authentik-compatible OAuth2/OIDC SSO for NodeBB with issuer-qualified OIDC identity mapping.

## Features

- Adds `/auth/authentik` and `/auth/authentik/callback` through NodeBB's SSO strategy flow.
- Uses exact OIDC `issuer + sub` as the permanent external identity.
- Does not auto-link existing local NodeBB accounts by email unless the explicit trusted-email migration policy is enabled.
- Trusted-email migration requires a pre-confirmed local email and blocks local admin/moderator accounts.
- Rejects missing email for all identities and rejects unverified email for unlinked identities.
- Rejects `sub`/email collisions instead of silently creating duplicate users.
- Keeps username display-only and never uses it for identity matching.
- Can run in link-only mode by disabling new SSO account creation so only already-linked OIDC subjects can log in.
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
- Launch URL: the NodeBB OIDC start URL, for example `https://forum.example.com/auth/authentik`
- Scopes: `openid email profile`
- Optional single logout: enable OIDC back-channel logout and set Authentik's back-channel logout URI to the URL shown in the plugin ACP page

Use the issuer URL from Authentik in the plugin settings and click Discover to populate endpoints. For Authentik-side enrollment, email-verification, duplicate-account, account-selection, and logout guidance, see [Authentik setup and enrollment hardening](docs/AUTHENTIK_SETUP.md).

PKCE is always enabled and cannot be disabled from the ACP. The plugin rejects `offline_access` scopes because refresh tokens are not used or stored. Confidential-client token exchange defaults to `client_secret_basic`; use `client_secret_post` only if the provider requires it. ID and logout token signing algorithms default to `RS256`; pin another supported asymmetric algorithm only if Authentik is configured to use it.

Optional provider authorization parameters can be configured as a query string, for example:

```text
prompt=login
```

By default, the plugin sends `prompt=login` and `max_age=0` so Authentik enrollment and linking screens do not silently reuse another Authentik browser session. This avoids confusing account-selection screens where a new enrollment can show the avatar for an already-authenticated Authentik account. Disable "Force fresh Authentik login" only if your Authentik flow already makes account selection explicit. The plugin rejects attempts to override protocol-critical parameters such as `state`, `nonce`, `client_id`, `redirect_uri`, and `scope`.

If Authentik still shows a previous user's current-session card or avatar during new enrollment, enable "Clear Authentik session before login". If the discovered OIDC end-session endpoint routes into the enrollment flow instead of clearing the browser session, set "Session clear endpoint override" to an Authentik invalidation/logout flow such as `https://auth.example.com/if/flow/default-invalidation-flow/` and set the return parameter to `next`. With `next`, the plugin returns to Authentik's authorization endpoint directly after session clearing so Authentik does not have to allow an external `next` URL.

If NodeBB should behave as Authentik-primary for sign-in, enable "Redirect anonymous login page to Authentik" in the plugin ACP. Anonymous `/login` requests will start the OIDC flow, while `/login?local=1` remains available for the local NodeBB login form. For launch from the Authentik application portal, configure the Authentik application's launch URL to NodeBB's `/auth/authentik` URL. An existing Authentik browser session only becomes a NodeBB session after the browser is redirected through that OIDC start URL and callback. If you want that portal launch to pass through silently when the user is already authenticated in Authentik, disable "Force fresh Authentik login"; leaving it enabled intentionally asks Authentik to re-authenticate or reselect the account.

## Operational Notes

NodeBB can only enforce identity rules after Authentik returns OIDC claims. Configure Authentik enrollment flows to reject missing email, duplicate emails, and duplicate usernames before provider-side account creation completes.

Authentik 2025.10 and newer default the standard email scope's `email_verified` claim to `false`; older Authentik releases may have emitted `true` by default. Use an explicit Authentik email scope mapping that reflects your real verification state, then confirm the actual ID token or userinfo response contains the expected boolean value.

If testing unverified email behavior, inspect the actual OIDC ID token or userinfo response. Authentik custom attributes do not necessarily change the emitted `email_verified` claim.

Use Identity Mapping Diagnostics in the ACP to audit subject mappings. New logins are keyed by exact `issuer + sub`; legacy `sub`-only mappings are read only when the linked user's stored issuer exactly matches the current issuer. Stale mappings to missing users fail closed and require explicit admin repair.

Use Last failure in the ACP diagnostics section when an OIDC callback is rejected. It stores only sanitized metadata such as rejection code, claim presence, `email_verified` type/value, issuer metadata, and whether userinfo was used. It does not store raw tokens, authorization codes, full claim payloads, or email addresses.

Use Last authorization when debugging Authentik session/avatar contamination. For clear-session preflight requests it records the sanitized provider logout/invalidation target, the configured return parameter, and whether the return target was converted to a provider-relative authorization URL.

Provider URLs and self-service links must be HTTPS by default and cannot target localhost or private network addresses. The callback HTTP exception and provider-loopback HTTP exception are separate local-development controls; keep both disabled in production.

The username collision policy defaults to creating a safe unique NodeBB username for new SSO users. Set it to reject if new SSO account creation should fail when the provider's display username conflicts with an existing NodeBB username/userslug.

Disable new SSO account creation when the forum should accept only users who already have a linked Authentik subject. A verified email match alone does not bind a new OIDC subject to an existing local account under the default policy. The trusted verified-email migration policy is intentionally narrower: the local account email must already be confirmed, and privileged local accounts are not linked automatically.

Optional Authentik self-service URLs can be configured in the ACP. When set, linked users see those external profile, password, MFA, and session-management links on `/user/<userslug>/authentik-oidc`.

Closing sessions from Authentik requires Authentik Single Logout to be configured. Enable OIDC back-channel logout in this plugin's ACP page, configure the displayed back-channel logout URL as the Authentik provider's Logout URI, set Logout Method to Back-channel, and ensure Authentik can reach the NodeBB public URL. The plugin validates the signed logout token and revokes the mapped NodeBB session for a stored OIDC `sid` when possible, falling back to uid-wide revocation for subject-only logout.

Back-channel logout is triggered only when Authentik terminates the user session and identifies an active OIDC provider session for NodeBB. Revoking consent for the NodeBB application is not a logout signal by itself. If deleting an Authentik session does not log the user out of NodeBB, open the plugin ACP diagnostics and click Last logout:

- No record: Authentik did not POST to NodeBB, or the request did not reach NodeBB.
- `outcome: rejected`: Authentik called NodeBB, but logout-token validation failed. Check issuer, client id/audience, JWKS URI, and signing key support.
- `outcome: unmatched`: the logout token was valid, but its `sub`/`sid` did not match a stored NodeBB mapping. Log into NodeBB through Authentik again, then retry.
- `outcome: revoked`: NodeBB revoked the mapped session or, for subject-only logout, sessions for the mapped uid. Refresh the browser or try a protected action to confirm the old session is gone.

After changing Authentik logout settings, log out of NodeBB and log back in through Authentik once so Authentik and the plugin both have a fresh provider-session record.

Display name synchronization is disabled by default. When enabled, successful SSO logins update NodeBB `fullname` from the provider's OIDC `name` claim after the account has already been resolved by issuer-qualified `sub`. Missing `name` claims do not blank the local field, and reserved staff/system names are skipped for non-privileged users.

Clustered NodeBB deployments must use a shared NodeBB session store. OIDC state, nonce, and PKCE verifier data live in the user's NodeBB session and deliberately have no process-memory fallback.

For production, prefer setting `AUTHENTIK_OIDC_CLIENT_SECRET` in the environment instead of storing the OAuth client secret only in NodeBB plugin settings. If using ACP-stored secrets, protect NodeBB database backups and settings exports as sensitive material.

## Tests

```bash
npm test
```

Additional planning and operating notes:

- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Security notes](docs/SECURITY.md)
- [Test checklist](docs/TEST_CHECKLIST.md)
- [Next steps](docs/NEXT_STEPS.md)
