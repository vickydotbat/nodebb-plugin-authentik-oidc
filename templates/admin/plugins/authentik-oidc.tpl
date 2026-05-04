<div class="acp-page-container">
	<div class="d-flex justify-content-between align-items-center mb-4">
		<h1>Authentik OIDC</h1>
		<button type="button" class="btn btn-primary" data-action="save">
			<i class="fa fa-save"></i> [[admin/admin:save]]
		</button>
	</div>

	<div class="row">
		<div class="col-lg-8">
			<form class="authentik-oidc-settings">
				<div class="form-check form-switch mb-3">
					<input class="form-check-input" type="checkbox" id="enabled" data-authentik-field="enabled">
					<label class="form-check-label" for="enabled">Enable Authentik OIDC login</label>
				</div>

				<div class="mb-3">
					<label class="form-label" for="displayName">Display name</label>
					<input class="form-control" id="displayName" type="text" data-authentik-field="displayName">
				</div>

				<div class="mb-3">
					<label class="form-label" for="clientId">Client ID</label>
					<input class="form-control" id="clientId" type="text" autocomplete="off" data-authentik-field="clientId">
					<div class="form-text text-danger" data-authentik-error="clientId"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="clientSecret">Client secret</label>
					<input class="form-control" id="clientSecret" type="password" autocomplete="new-password" data-authentik-field="clientSecret">
					<div class="form-text">Leave unchanged to preserve the saved secret.</div>
					<div class="form-text text-danger" data-authentik-error="clientSecret"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="issuer">Issuer</label>
					<div class="input-group">
						<input class="form-control" id="issuer" type="url" data-authentik-field="issuer">
						<button class="btn btn-outline-secondary" type="button" data-action="discover">
							<i class="fa fa-search"></i> Discover
						</button>
					</div>
					<div class="form-text text-danger" data-authentik-error="issuer"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="authorizationEndpoint">Authorization endpoint</label>
					<input class="form-control" id="authorizationEndpoint" type="url" data-authentik-field="authorizationEndpoint">
					<div class="form-text text-danger" data-authentik-error="authorizationEndpoint"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="tokenEndpoint">Token endpoint</label>
					<input class="form-control" id="tokenEndpoint" type="url" data-authentik-field="tokenEndpoint">
					<div class="form-text text-danger" data-authentik-error="tokenEndpoint"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="userinfoEndpoint">Userinfo endpoint</label>
					<input class="form-control" id="userinfoEndpoint" type="url" data-authentik-field="userinfoEndpoint">
					<div class="form-text text-danger" data-authentik-error="userinfoEndpoint"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="jwksUri">JWKS URI</label>
					<div class="input-group">
						<input class="form-control" id="jwksUri" type="url" data-authentik-field="jwksUri">
						<button class="btn btn-outline-secondary" type="button" data-action="test-jwks">
							<i class="fa fa-key"></i> Test JWKS
						</button>
					</div>
					<div class="form-text text-danger" data-authentik-error="jwksUri"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="scopes">Scopes</label>
					<input class="form-control" id="scopes" type="text" data-authentik-field="scopes">
					<div class="form-text text-danger" data-authentik-error="scopes"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="authorizationParameters">Authorization parameters</label>
					<input class="form-control" id="authorizationParameters" type="text" placeholder="prompt=login" data-authentik-field="authorizationParameters">
					<div class="form-text">Optional query string parameters sent to the provider. Plugin-controlled parameters cannot be overridden.</div>
					<div class="form-text text-danger" data-authentik-error="authorizationParameters"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="selfServiceProfileUrl">Self-service profile URL</label>
					<input class="form-control" id="selfServiceProfileUrl" type="url" data-authentik-field="selfServiceProfileUrl">
					<div class="form-text text-danger" data-authentik-error="selfServiceProfileUrl"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="selfServicePasswordUrl">Self-service password URL</label>
					<input class="form-control" id="selfServicePasswordUrl" type="url" data-authentik-field="selfServicePasswordUrl">
					<div class="form-text text-danger" data-authentik-error="selfServicePasswordUrl"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="selfServiceMfaUrl">Self-service MFA URL</label>
					<input class="form-control" id="selfServiceMfaUrl" type="url" data-authentik-field="selfServiceMfaUrl">
					<div class="form-text text-danger" data-authentik-error="selfServiceMfaUrl"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="selfServiceSessionsUrl">Self-service sessions URL</label>
					<input class="form-control" id="selfServiceSessionsUrl" type="url" data-authentik-field="selfServiceSessionsUrl">
					<div class="form-text text-danger" data-authentik-error="selfServiceSessionsUrl"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="usernameCollisionPolicy">Username collision policy</label>
					<select class="form-select" id="usernameCollisionPolicy" data-authentik-field="usernameCollisionPolicy">
						<option value="unique">Create a unique NodeBB username</option>
						<option value="reject">Reject new SSO account creation</option>
					</select>
				</div>

				<div class="mb-3">
					<label class="form-label" for="callbackUrl">Callback URL</label>
					<div class="input-group">
						<input class="form-control" id="callbackUrl" type="text" readonly data-authentik-field="callbackUrl">
						<button class="btn btn-outline-secondary" type="button" data-action="copy-callback-url">
							<i class="fa fa-copy"></i>
						</button>
					</div>
					<div class="form-text text-danger" data-authentik-error="callbackUrl"></div>
				</div>

				<div class="form-check form-switch mb-3">
					<input class="form-check-input" type="checkbox" id="backchannelLogoutEnabled" data-authentik-field="backchannelLogoutEnabled">
					<label class="form-check-label" for="backchannelLogoutEnabled">Enable OIDC back-channel logout</label>
					<div class="form-text">Configure this URL as Authentik's back-channel logout URI so Authentik session closure revokes NodeBB sessions.</div>
				</div>

				<div class="form-check form-switch mb-3">
					<input class="form-check-input" type="checkbox" id="allowAccountCreation" data-authentik-field="allowAccountCreation">
					<label class="form-check-label" for="allowAccountCreation">Allow new SSO account creation</label>
					<div class="form-text">When disabled, only an existing linked subject or a verified email match can log in.</div>
				</div>

				<div class="form-check form-switch mb-3">
					<input class="form-check-input" type="checkbox" id="syncFullnameOnLogin" data-authentik-field="syncFullnameOnLogin">
					<label class="form-check-label" for="syncFullnameOnLogin">Sync display name from OIDC name claim</label>
					<div class="form-text">When enabled, successful SSO logins update NodeBB fullname from the provider after identity resolution succeeds.</div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="backchannelLogoutUrl">Back-channel logout URL</label>
					<div class="input-group">
						<input class="form-control" id="backchannelLogoutUrl" type="text" readonly data-authentik-field="backchannelLogoutUrl">
						<button class="btn btn-outline-secondary" type="button" data-action="copy-backchannel-logout-url">
							<i class="fa fa-copy"></i>
						</button>
					</div>
					<div class="form-text text-danger" data-authentik-error="backchannelLogoutUrl"></div>
				</div>

				<div class="form-check form-switch mb-3">
					<input class="form-check-input" type="checkbox" id="usePkce" data-authentik-field="usePkce">
					<label class="form-check-label" for="usePkce">Use PKCE</label>
				</div>

				<div class="form-check form-switch mb-3">
					<input class="form-check-input" type="checkbox" id="allowInsecureCallbackUrlForDevelopment" data-authentik-field="allowInsecureCallbackUrlForDevelopment">
					<label class="form-check-label" for="allowInsecureCallbackUrlForDevelopment">Allow HTTP callback URL for localhost development</label>
				</div>
			</form>

			<hr>

			<section class="authentik-oidc-diagnostics">
				<div class="d-flex justify-content-between align-items-center mb-3">
					<h2 class="h4 mb-0">Identity Mapping Diagnostics</h2>
					<div class="btn-group">
						<button type="button" class="btn btn-outline-secondary" data-action="audit-mappings">
							<i class="fa fa-list-check"></i> Audit mappings
						</button>
						<button type="button" class="btn btn-outline-secondary" data-action="show-last-failure">
							<i class="fa fa-circle-exclamation"></i> Last failure
						</button>
						<button type="button" class="btn btn-outline-danger" data-action="repair-stale-mappings" disabled>
							<i class="fa fa-trash"></i> Repair stale
						</button>
					</div>
				</div>
				<p class="text-muted" data-authentik-audit-summary>Run an audit to inspect Authentik subject mappings.</p>
				<div class="table-responsive">
					<table class="table table-sm">
						<thead>
							<tr>
								<th>Issue</th>
								<th>UID</th>
								<th>Subject</th>
							</tr>
						</thead>
						<tbody data-authentik-audit-results>
							<tr>
								<td colspan="3" class="text-muted">No audit has run yet.</td>
							</tr>
						</tbody>
					</table>
				</div>
				<pre class="border rounded p-3 bg-light text-body-secondary" data-authentik-last-failure>No failure diagnostics loaded.</pre>
				<pre class="border rounded p-3 bg-light text-body-secondary" data-authentik-jwks-result>No JWKS test has run yet.</pre>
			</section>
		</div>
	</div>
</div>
