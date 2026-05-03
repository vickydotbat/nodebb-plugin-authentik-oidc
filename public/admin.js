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

	Admin.init = async function () {
		fill(await get('/settings'));

		$('[data-action="copy-callback-url"]').on('click', async function () {
			await navigator.clipboard.writeText($('[data-authentik-field="callbackUrl"]').val());
			alerts.success('Callback URL copied');
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
	};

	return Admin;
});
