'use strict';

const nconf = require.main.require('nconf');
const meta = require.main.require('./src/meta');

const SETTINGS_KEY = 'authentik-oidc';
const SECRET_PLACEHOLDER = '********';
const DEFAULTS = {
	enabled: false,
	clientId: '',
	clientSecret: '',
	issuer: '',
	authorizationEndpoint: '',
	tokenEndpoint: '',
	userinfoEndpoint: '',
	jwksUri: '',
	scopes: 'openid email profile',
	authorizationParameters: '',
	selfServiceProfileUrl: '',
	selfServicePasswordUrl: '',
	selfServiceMfaUrl: '',
	selfServiceSessionsUrl: '',
	displayName: 'Authentik',
	allowInsecureCallbackUrlForDevelopment: false,
	usePkce: true,
	usernameCollisionPolicy: 'unique',
};

function booleanValue(value) {
	return value === true || value === 'true' || value === 1 || value === '1' || value === 'on';
}

function trimString(value) {
	return typeof value === 'string' ? value.trim() : '';
}

function normalizeSettings(raw) {
	const settings = { ...DEFAULTS, ...(raw || {}) };
	settings.enabled = booleanValue(settings.enabled);
	settings.allowInsecureCallbackUrlForDevelopment = booleanValue(settings.allowInsecureCallbackUrlForDevelopment);
	settings.usePkce = settings.usePkce === undefined ? true : booleanValue(settings.usePkce);
	[
		'clientId',
		'clientSecret',
		'issuer',
		'authorizationEndpoint',
		'tokenEndpoint',
		'userinfoEndpoint',
		'jwksUri',
		'scopes',
		'authorizationParameters',
		'selfServiceProfileUrl',
		'selfServicePasswordUrl',
		'selfServiceMfaUrl',
		'selfServiceSessionsUrl',
		'displayName',
		'usernameCollisionPolicy',
	].forEach((key) => {
		settings[key] = trimString(settings[key]);
	});
	if (!['unique', 'reject'].includes(settings.usernameCollisionPolicy)) {
		settings.usernameCollisionPolicy = DEFAULTS.usernameCollisionPolicy;
	}
	return settings;
}

function publicSettings(settings) {
	const output = { ...settings };
	output.clientSecret = settings.clientSecret ? SECRET_PLACEHOLDER : '';
	output.callbackUrl = getCallbackUrl();
	return output;
}

function getCallbackUrl() {
	const baseUrl = nconf.get('url') || '';
	return `${baseUrl.replace(/\/+$/, '')}/auth/authentik/callback`;
}

function isLoopbackHttp(url) {
	return url.protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
}

function validateUrl(value, field, errors, { required = true, allowHttp = false } = {}) {
	if (!value) {
		if (required) {
			errors[field] = 'Required';
		}
		return;
	}
	try {
		const url = new URL(value);
		if (url.protocol !== 'https:' && !(allowHttp && isLoopbackHttp(url))) {
			errors[field] = 'Must be an HTTPS URL';
		}
	} catch (err) {
		errors[field] = 'Must be a valid URL';
	}
}

function validate(settings, { requireSecret = false } = {}) {
	const errors = {};
	const allowHttp = settings.allowInsecureCallbackUrlForDevelopment;
	if (settings.enabled) {
		if (!settings.clientId) {
			errors.clientId = 'Required';
		}
		if (requireSecret && !settings.clientSecret) {
			errors.clientSecret = 'Required';
		}
		if (!settings.scopes.split(/\s+/).includes('openid')) {
			errors.scopes = 'Must include openid';
		}
		validateAuthorizationParameters(settings.authorizationParameters, errors);
		validateUrl(settings.issuer, 'issuer', errors, { allowHttp });
		validateUrl(settings.authorizationEndpoint, 'authorizationEndpoint', errors, { allowHttp });
		validateUrl(settings.tokenEndpoint, 'tokenEndpoint', errors, { allowHttp });
		validateUrl(settings.userinfoEndpoint, 'userinfoEndpoint', errors, { allowHttp });
		validateUrl(settings.jwksUri, 'jwksUri', errors, { allowHttp });
		validateUrl(settings.selfServiceProfileUrl, 'selfServiceProfileUrl', errors, { required: false, allowHttp });
		validateUrl(settings.selfServicePasswordUrl, 'selfServicePasswordUrl', errors, { required: false, allowHttp });
		validateUrl(settings.selfServiceMfaUrl, 'selfServiceMfaUrl', errors, { required: false, allowHttp });
		validateUrl(settings.selfServiceSessionsUrl, 'selfServiceSessionsUrl', errors, { required: false, allowHttp });
		validateUrl(getCallbackUrl(), 'callbackUrl', errors, { allowHttp });
	}
	return errors;
}

function validateAuthorizationParameters(value, errors) {
	if (!value) {
		return;
	}
	let params;
	try {
		params = new URLSearchParams(value);
	} catch (err) {
		errors.authorizationParameters = 'Must use query string format, for example prompt=login';
		return;
	}
	const protectedParams = new Set([
		'client_id',
		'code_challenge',
		'code_challenge_method',
		'nonce',
		'redirect_uri',
		'response_type',
		'scope',
		'state',
	]);
	for (const key of params.keys()) {
		if (protectedParams.has(key)) {
			errors.authorizationParameters = `${key} is controlled by the plugin`;
			return;
		}
	}
}

async function getSettings() {
	return normalizeSettings(await meta.settings.get(SETTINGS_KEY));
}

async function ensureDefaults() {
	await meta.settings.setOnEmpty(SETTINGS_KEY, DEFAULTS);
}

async function saveSettings(input) {
	const current = await getSettings();
	const next = normalizeSettings({ ...current, ...(input || {}) });
	if (!Object.prototype.hasOwnProperty.call(input || {}, 'clientSecret') ||
			next.clientSecret === '' ||
			next.clientSecret === SECRET_PLACEHOLDER) {
		next.clientSecret = current.clientSecret;
	}
	const errors = validate(next, { requireSecret: next.enabled });
	if (Object.keys(errors).length) {
		const err = new Error('Settings validation failed');
		err.statusCode = 400;
		err.errors = errors;
		throw err;
	}
	await meta.settings.set(SETTINGS_KEY, next);
	return publicSettings(next);
}

module.exports = {
	SETTINGS_KEY,
	SECRET_PLACEHOLDER,
	DEFAULTS,
	ensureDefaults,
	getSettings,
	getCallbackUrl,
	normalizeSettings,
	publicSettings,
	saveSettings,
	validate,
	validateAuthorizationParameters,
};
