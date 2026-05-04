<div class="account authentik-oidc-account w-100 mx-auto">
	<div class="d-flex flex-column flex-md-row gap-3 align-items-md-center justify-content-between border-bottom pb-3 mb-4">
		<div>
			<h2 class="fw-semibold fs-4 mb-1">{authentikOidc.providerName} account</h2>
			<p class="text-muted mb-0">@{username}</p>
		</div>
		<a href="{config.relative_path}/user/{userslug}/settings" class="btn btn-light">
			<i class="fa fa-gear"></i> [[user:settings]]
		</a>
	</div>

	{{{ if authentikOidc.linked }}}
	<div class="d-grid gap-3">
		<section class="border rounded p-3">
			<h3 class="fs-5 fw-semibold mb-3">Linked account</h3>
			<dl class="row mb-0">
				<dt class="col-sm-4">Provider</dt>
				<dd class="col-sm-8">{authentikOidc.providerName}</dd>

				<dt class="col-sm-4">Issuer</dt>
				<dd class="col-sm-8 text-break">{authentikOidc.issuer}</dd>

				<dt class="col-sm-4">Linked</dt>
				<dd class="col-sm-8">{{{ if authentikOidc.linkedAt }}}{authentikOidc.linkedAt}{{{ else }}}Unknown{{{ end }}}</dd>

				<dt class="col-sm-4">Last login</dt>
				<dd class="col-sm-8">{{{ if authentikOidc.lastLoginAt }}}{authentikOidc.lastLoginAt}{{{ else }}}Unknown{{{ end }}}</dd>

				<dt class="col-sm-4">Last sync</dt>
				<dd class="col-sm-8">{{{ if authentikOidc.lastSyncedAt }}}{authentikOidc.lastSyncedAt}{{{ else }}}Not synced{{{ end }}}</dd>

				<dt class="col-sm-4">Last provider email</dt>
				<dd class="col-sm-8">{{{ if authentikOidc.lastProviderEmail }}}{authentikOidc.lastProviderEmail}{{{ else }}}Unknown{{{ end }}}</dd>
			</dl>
		</section>

		<section class="border rounded p-3">
			<h3 class="fs-5 fw-semibold mb-3">Managed fields</h3>
			{{{ if authentikOidc.managedFields.length }}}
			<ul class="list-unstyled mb-0">
				{{{ each authentikOidc.managedFields }}}
				<li><span class="badge text-bg-secondary">{./}</span></li>
				{{{ end }}}
			</ul>
			{{{ else }}}
			<p class="text-muted mb-0">No profile synchronization fields are enabled.</p>
			{{{ end }}}
		</section>

		{{{ if authentikOidc.hasExternalLinks }}}
		<section class="border rounded p-3">
			<h3 class="fs-5 fw-semibold mb-3">Provider actions</h3>
			<div class="d-flex flex-wrap gap-2">
				{{{ each authentikOidc.externalLinks }}}
				<a class="btn btn-outline-secondary" href="{./url}" rel="noopener noreferrer" target="_blank">
					<i class="fa {./icon}"></i> {./label}
				</a>
				{{{ end }}}
			</div>
		</section>
		{{{ end }}}
	</div>
	{{{ else }}}
	<section class="border rounded p-3">
		<h3 class="fs-5 fw-semibold mb-2">No linked account</h3>
		<p class="text-muted mb-0">This NodeBB account is not linked to {authentikOidc.providerName}.</p>
	</section>
	{{{ end }}}
</div>
