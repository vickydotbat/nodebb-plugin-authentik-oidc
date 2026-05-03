# Security Notes

`nodebb-plugin-authentik-oidc` treats the OIDC `sub` claim as the permanent external identity. Email is only a secondary linking mechanism and only when `email_verified` is the boolean `true`.

The plugin deliberately rejects logins when:

- `sub` is missing.
- `email` is missing.
- `email_verified` is missing, false, or a non-boolean value.
- An existing `sub` mapping and verified email point to different NodeBB users.
- A verified email belongs to a NodeBB account already linked to another `sub`.
- ID token and userinfo `sub` values differ.

The plugin never links or finds accounts by username. `preferred_username` and `name` are only used to seed the initial display username for newly created NodeBB users.

Secrets, authorization codes, access tokens, refresh tokens, and raw ID tokens must not be logged. Admin settings responses show only a placeholder when a client secret is saved.
