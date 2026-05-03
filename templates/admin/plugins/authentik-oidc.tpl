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
					<input class="form-control" id="jwksUri" type="url" data-authentik-field="jwksUri">
					<div class="form-text text-danger" data-authentik-error="jwksUri"></div>
				</div>

				<div class="mb-3">
					<label class="form-label" for="scopes">Scopes</label>
					<input class="form-control" id="scopes" type="text" data-authentik-field="scopes">
					<div class="form-text text-danger" data-authentik-error="scopes"></div>
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
					<input class="form-check-input" type="checkbox" id="usePkce" data-authentik-field="usePkce">
					<label class="form-check-label" for="usePkce">Use PKCE</label>
				</div>

				<div class="form-check form-switch mb-3">
					<input class="form-check-input" type="checkbox" id="allowInsecureCallbackUrlForDevelopment" data-authentik-field="allowInsecureCallbackUrlForDevelopment">
					<label class="form-check-label" for="allowInsecureCallbackUrlForDevelopment">Allow HTTP callback URL for localhost development</label>
				</div>
			</form>
		</div>
	</div>
</div>
