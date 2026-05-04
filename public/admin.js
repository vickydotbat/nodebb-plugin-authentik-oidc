'use strict';

define('admin/plugins/authentik-oidc', ['alerts'], function (alerts) {
	const Admin = {};
	const apiBase = `${config.relative_path}/api/v3/plugins/authentik-oidc`;

	async function request(path, options) {
		const response = await fetch(`${apiBase}${path}`, {
			...options,
			headers: {
				accept: 'application/json',
				...(options && options.headers ? options.headers : {}),
			},
		});
		const body = await response.json();
		const payload = body && body.hasOwnProperty('response') ? body.response : body;
		if (!response.ok) {
			const error = new Error(payload.message || payload.error || response.statusText);
			error.errors = payload.errors || {};
			throw error;
		}
		return payload;
	}

	function get(path) {
		return request(path);
	}

	function post(path, data) {
		return request(path, {
			method: 'POST',
			headers: {
				'content-type': 'application/json; charset=utf-8',
				'x-csrf-token': config.csrf_token,
			},
			body: JSON.stringify(data || {}),
		});
	}

	function formData() {
		const data = {};
		$('[data-authentik-field]').each(function () {
			const field = $(this).attr('data-authentik-field');
			if ($(this).attr('type') === 'checkbox') {
				data[field] = $(this).is(':checked');
			} else {
				data[field] = $(this).val();
			}
		});
		return data;
	}

	function fill(settings) {
		Object.keys(settings).forEach((field) => {
			const input = $(`[data-authentik-field="${field}"]`);
			if (!input.length) {
				return;
			}
			if (input.attr('type') === 'checkbox') {
				input.prop('checked', !!settings[field]);
			} else {
				input.val(settings[field] || '');
			}
		});
	}

	function showErrors(errors) {
		$('[data-authentik-error]').text('');
		Object.keys(errors || {}).forEach((field) => {
			$(`[data-authentik-error="${field}"]`).text(errors[field]);
		});
	}

	function escapeHtml(value) {
		return String(value || '').replace(/[&<>"']/g, function (char) {
			return {
				'&': '&amp;',
				'<': '&lt;',
				'>': '&gt;',
				'"': '&quot;',
				"'": '&#39;',
			}[char];
		});
	}

	function renderMappingAudit(result) {
		const summary = result.summary || {};
		$('[data-authentik-audit-summary]').text([
			`${summary.mappings || 0} mappings`,
			`${summary.linkedUsers || 0} linked users`,
			`${summary.staleMappings || 0} stale`,
			`${summary.reverseMissing || 0} missing reverse`,
			`${summary.reverseConflicts || 0} conflicts`,
			`${summary.duplicateUserLinks || 0} duplicate user links`,
		].join(' | '));

		const rows = [];
		(result.staleMappings || []).forEach((entry) => {
			rows.push(`<tr><td>Stale mapping</td><td>${escapeHtml(entry.uid)}</td><td><code>${escapeHtml(entry.sub)}</code></td></tr>`);
		});
		(result.reverseMissing || []).forEach((entry) => {
			rows.push(`<tr><td>Missing reverse mapping</td><td>${escapeHtml(entry.uid)}</td><td><code>${escapeHtml(entry.sub)}</code></td></tr>`);
		});
		(result.reverseConflicts || []).forEach((entry) => {
			rows.push(`<tr><td>Reverse conflict</td><td>${escapeHtml(entry.uid)}</td><td><code>${escapeHtml(entry.sub)}</code></td></tr>`);
		});
		(result.duplicateUserLinks || []).forEach((entry) => {
			rows.push(`<tr><td>Duplicate user links</td><td>${escapeHtml(entry.users.map(user => user.uid).join(', '))}</td><td><code>${escapeHtml(entry.sub)}</code></td></tr>`);
		});
		$('[data-authentik-audit-results]').html(rows.join('') || '<tr><td colspan="3" class="text-muted">No mapping issues found.</td></tr>');
		$('[data-action="repair-stale-mappings"]').prop('disabled', !(summary.staleMappings > 0));
	}

	function renderLastFailure(result) {
		if (!result || !result.at) {
			$('[data-authentik-last-failure]').text('No failure diagnostics recorded.');
			return;
		}
		$('[data-authentik-last-failure]').text(JSON.stringify({
			at: new Date(parseInt(result.at, 10)).toISOString(),
			stage: result.stage,
			code: result.code,
			message: result.message,
			level: result.level,
			configuredIssuer: result.configuredIssuer,
			userinfoUsed: result.userinfoUsed,
			idTokenClaims: result.idTokenClaims,
			userinfoClaims: result.userinfoClaims,
			mergedClaims: result.mergedClaims,
		}, null, 2));
	}

	function renderLastLogout(result) {
		if (!result || !result.at) {
			$('[data-authentik-last-logout]').text('No back-channel logout request recorded.');
			return;
		}
		$('[data-authentik-last-logout]').text(JSON.stringify({
			at: new Date(parseInt(result.at, 10)).toISOString(),
			stage: result.stage,
			outcome: result.outcome,
			enabled: result.enabled,
			hasLogoutToken: result.hasLogoutToken,
			tokenValidated: result.tokenValidated,
			hasSub: result.hasSub,
			hasSid: result.hasSid,
			uid: result.uid,
			source: result.source,
			code: result.code,
			message: result.message,
			statusCode: result.statusCode,
		}, null, 2));
	}

	function renderLastAuthorization(result) {
		if (!result || !result.at) {
			$('[data-authentik-last-authorization]').text('No authorization-start diagnostics recorded.');
			return;
		}
		$('[data-authentik-last-authorization]').text(JSON.stringify({
			at: new Date(parseInt(result.at, 10)).toISOString(),
			stage: result.stage,
			clearProviderSessionBeforeLogin: result.clearProviderSessionBeforeLogin,
			forceProviderLogin: result.forceProviderLogin,
			hasEndSessionEndpoint: result.hasEndSessionEndpoint,
			sessionClearEndpointOverride: result.sessionClearEndpointOverride,
			sessionClearReturnParameter: result.sessionClearReturnParameter,
			authorizationParameters: result.authorizationParameters,
			redirectTarget: result.redirectTarget,
			returnTo: result.returnTo,
			returnToWasProviderRelative: result.returnToWasProviderRelative,
		}, null, 2));
	}

	function renderJwksResult(result) {
		$('[data-authentik-jwks-result]').text(JSON.stringify({
			jwksUri: result.jwksUri,
			keyCount: result.keyCount,
			supportedSigningKeyCount: result.supportedSigningKeyCount,
			keyTypes: result.keyTypes,
			algorithms: result.algorithms,
			hasKeyIds: result.hasKeyIds,
		}, null, 2));
	}

	Admin.init = async function () {
		fill(await get('/settings'));

		$('[data-action="copy-callback-url"]').on('click', async function () {
			await navigator.clipboard.writeText($('[data-authentik-field="callbackUrl"]').val());
			alerts.success('Callback URL copied');
		});

		$('[data-action="copy-backchannel-logout-url"]').on('click', async function () {
			await navigator.clipboard.writeText($('[data-authentik-field="backchannelLogoutUrl"]').val());
			alerts.success('Back-channel logout URL copied');
		});

		$('[data-action="discover"]').on('click', async function () {
			showErrors({});
			try {
				const metadata = await post('/discover', {
					issuer: $('[data-authentik-field="issuer"]').val(),
				});
				fill(metadata);
				alerts.success('OIDC discovery succeeded');
			} catch (err) {
				alerts.error(err.message || 'OIDC discovery failed');
			}
		});

		$('[data-action="test-jwks"]').on('click', async function () {
			showErrors({});
			try {
				renderJwksResult(await post('/jwks/test', {
					jwksUri: $('[data-authentik-field="jwksUri"]').val(),
				}));
				alerts.success('JWKS test succeeded');
			} catch (err) {
				alerts.error(err.message || 'JWKS test failed');
			}
		});

		$('[data-action="save"]').on('click', async function () {
			showErrors({});
			try {
				fill(await post('/settings', formData()));
				alerts.success('[[success:settings-saved]]');
			} catch (err) {
				if (err.errors) {
					showErrors(err.errors);
				}
				alerts.error(err.message || 'Settings save failed');
			}
		});

		$('[data-action="audit-mappings"]').on('click', async function () {
			try {
				renderMappingAudit(await get('/mappings/audit'));
				alerts.success('Mapping audit completed');
			} catch (err) {
				alerts.error(err.message || 'Mapping audit failed');
			}
		});

		$('[data-action="show-last-failure"]').on('click', async function () {
			try {
				renderLastFailure(await get('/diagnostics/last-failure'));
				alerts.success('Loaded last failure diagnostics');
			} catch (err) {
				alerts.error(err.message || 'Failed to load diagnostics');
			}
		});

		$('[data-action="show-last-logout"]').on('click', async function () {
			try {
				renderLastLogout(await get('/diagnostics/last-logout'));
				alerts.success('Loaded last logout diagnostics');
			} catch (err) {
				alerts.error(err.message || 'Failed to load logout diagnostics');
			}
		});

		$('[data-action="show-last-authorization"]').on('click', async function () {
			try {
				renderLastAuthorization(await get('/diagnostics/last-authorization'));
				alerts.success('Loaded last authorization diagnostics');
			} catch (err) {
				alerts.error(err.message || 'Failed to load authorization diagnostics');
			}
		});

		$('[data-action="repair-stale-mappings"]').on('click', async function () {
			if (!window.confirm('Remove stale Authentik subject mappings that point to missing NodeBB users?')) {
				return;
			}
			try {
				const result = await post('/mappings/repair-stale', { confirm: true });
				alerts.success(`Removed ${result.removed || 0} stale mappings`);
				renderMappingAudit(await get('/mappings/audit'));
			} catch (err) {
				alerts.error(err.message || 'Stale mapping repair failed');
			}
		});
	};

	return Admin;
});
