# Authentik Setup And Enrollment Hardening

This guide describes the Authentik-side configuration that should be paired with `nodebb-plugin-authentik-oidc`.

The plugin prevents duplicate NodeBB accounts after Authentik returns OIDC claims. Authentik still owns the upstream registration, login, email verification, MFA, account-selection, and logout experience. Configure Authentik so invalid identities are stopped before the user is redirected back to NodeBB.

## OAuth2/OIDC Provider

Create an Authentik OAuth2/OpenID provider for NodeBB:

- Client type: confidential.
- Redirect URI: the callback URL shown in the NodeBB plugin ACP page.
- Scopes: `openid email profile`.
- Subject mode: stable per-user subject. Do not use username or email as the subject.
- Signing key: configured and exposed through the provider JWKS URI.
- Logout: optional, but recommended. Use back-channel logout with the back-channel logout URL shown in the NodeBB plugin ACP page.

Use issuer discovery from the plugin ACP after creating the provider. Save the exact discovered issuer and endpoints returned by Authentik.

## Required Claims

NodeBB login requires these OIDC claims:

- `sub`: permanent external identity.
- `email`: required for new links and new users.
- `email_verified`: must be the boolean `true` for new links and new users.
- `preferred_username`: optional, display-only seed for new NodeBB usernames.
- `name`: optional, used only when display-name sync is enabled.

Do not map `preferred_username`, username, slug, display name, or email into identity authority. The plugin uses only `sub` as the durable external identity and verified email as a secondary first-link mechanism.

## Email Verification Claim

Authentik versions differ in how the default email scope emits `email_verified`. Current Authentik documentation notes that releases before 2025.10 emitted `email_verified` as `True` from the default email scope, while 2025.10 and newer default it to `False` because Authentik has no universal authoritative email-verification source.

For this plugin, configure an explicit email scope mapping that reflects your real verification state. A conservative mapping is:

```python
return {
    "email": request.user.email,
    "email_verified": request.user.attributes.get("email_verified", False),
}
```

Only use an always-true mapping when every account reaching this provider has already completed a trustworthy email verification flow. If a test account should be rejected as unverified, verify the actual ID token or userinfo payload contains the boolean `false`; setting a custom attribute is not enough unless the scope mapping reads it.

## Enrollment Flow Guardrails

Use Authentik enrollment and policy configuration to reject bad registrations before Authentik creates or verifies an upstream account:

- Require email before enrollment can complete.
- Require whatever email-verification step your deployment treats as authoritative.
- Reject duplicate email addresses in Authentik before the provider redirects back to NodeBB.
- Reject duplicate usernames in Authentik when username uniqueness matters to operators or users.
- Avoid silently changing email, username, or profile fields during enrollment in ways the user cannot review.
- Keep NodeBB as the relying party only; do not use the NodeBB plugin to collect old NodeBB passwords or create Authentik users through a generic browser form.

The plugin will still fail closed if a verified email maps to a NodeBB account that is already linked to another Authentik `sub`, but by then the Authentik-side registration may already have completed. Authentik policies are the right place to stop that earlier.

## Account Selection And Session Reuse

When testing enrollment or linking, Authentik browser sessions can make the wrong upstream account appear selected. Use one of these controls:

- Test in a clean or incognito browser profile.
- Keep the plugin ACP "Force fresh Authentik login" setting enabled. It sends `prompt=login` and `max_age=0` unless you explicitly configure your own prompt parameters.
- Use `prompt=select_account` only if your Authentik version and flow support the expected account-selection behavior.
- Build an Authentik authorization flow that makes account selection visible when users commonly share browsers.

Do not work around account-selection confusion by matching NodeBB accounts on username. Username remains display-only.

## Self-Service Links

The plugin can show linked users external Authentik self-service actions on `/user/<userslug>/authentik-oidc`. Configure only URLs that are intended for end users:

- Profile settings.
- Password or recovery settings.
- MFA or device settings.
- Session management.

The plugin validates these links as HTTPS by default and does not expose OIDC subjects, raw claims, tokens, or mapping keys on the user-facing page.

## Back-Channel Logout

For upstream logout to revoke NodeBB sessions:

1. Enable OIDC back-channel logout in the plugin ACP.
2. Copy the displayed back-channel logout URL.
3. Configure the Authentik provider's back-channel logout URI or logout URI with back-channel method, depending on the Authentik version.
4. Ensure Authentik can reach the NodeBB public HTTPS URL.
5. Log out of NodeBB and log back in through Authentik once so both systems have a fresh provider session.
6. Terminate the Authentik session and confirm NodeBB ACP Last logout records `revoked`.

Back-channel logout is server-to-server. Front-channel logout and consent revocation are not equivalent guarantees.

## Release Verification

Before release, run these live checks against the intended Authentik provider:

- New verified Authentik account creates exactly one NodeBB account.
- Repeat login with the same Authentik user resolves the same NodeBB uid by `sub`.
- Existing NodeBB account with matching verified email links without duplicate creation.
- Missing email is rejected without user or mapping creation.
- Unverified email emits `email_verified: false` in the actual OIDC claims and is rejected.
- Duplicate Authentik email and duplicate Authentik username enrollment attempts are blocked by Authentik policy before callback when that is the desired operator policy.
- `prompt=login` or the chosen Authentik account-selection flow prevents accidental browser-session reuse during testing.
- Back-channel logout POSTs a `logout_token` and revokes the mapped NodeBB user's sessions when enabled.

## References

- Authentik OAuth2/OpenID provider documentation: https://docs.goauthentik.io/add-secure-apps/providers/oauth2/
- Authentik provider property mappings: https://docs.goauthentik.io/add-secure-apps/providers/property-mappings/
- Authentik front-channel and back-channel logout: https://docs.goauthentik.io/add-secure-apps/providers/oauth2/frontchannel_and_backchannel_logout/
