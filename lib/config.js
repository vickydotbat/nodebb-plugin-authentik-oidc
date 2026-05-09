'use strict';

const nconf = require.main.require('nconf');
const meta = require.main.require('./src/meta');
const net = require('node:net');

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
	endSessionEndpoint: '',
	scopes: 'openid email profile',
	authorizationParameters: '',
	forceProviderLogin: true,
	clearProviderSessionBeforeLogin: false,
	sessionClearEndpoint: '',
	sessionClearReturnParameter: 'post_logout_redirect_uri',
	selfServiceProfileUrl: '',
	selfServicePasswordUrl: '',
	selfServiceMfaUrl: '',
	selfServiceSessionsUrl: '',
	backchannelLogoutEnabled: false,
	displayName: 'Authentik',
	allowInsecureCallbackUrlForDevelopment: false,
	usePkce: true,
	redirectRegisterToLogin: true,
	allowAccountCreation: true,
	usernameCollisionPolicy: 'unique',
	syncFullnameOnLogin: false,
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
	settings.redirectRegisterToLogin = settings.redirectRegisterToLogin === undefined ? true : booleanValue(settings.redirectRegisterToLogin);
	settings.allowAccountCreation = settings.allowAccountCreation === undefined ? true : booleanValue(settings.allowAccountCreation);
	settings.backchannelLogoutEnabled = booleanValue(settings.backchannelLogoutEnabled);
	settings.syncFullnameOnLogin = booleanValue(settings.syncFullnameOnLogin);
	settings.forceProviderLogin = settings.forceProviderLogin === undefined ? true : booleanValue(settings.forceProviderLogin);
	settings.clearProviderSessionBeforeLogin = booleanValue(settings.clearProviderSessionBeforeLogin);
	[
		'clientId',
		'clientSecret',
		'issuer',
		'authorizationEndpoint',
		'tokenEndpoint',
		'userinfoEndpoint',
		'jwksUri',
		'endSessionEndpoint',
		'sessionClearEndpoint',
		'sessionClearReturnParameter',
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
	if (!['post_logout_redirect_uri', 'next'].includes(settings.sessionClearReturnParameter)) {
		settings.sessionClearReturnParameter = DEFAULTS.sessionClearReturnParameter;
	}
	return settings;
}

function publicSettings(settings) {
	const output = { ...settings };
	output.clientSecret = settings.clientSecret ? SECRET_PLACEHOLDER : '';
	output.callbackUrl = getCallbackUrl();
	output.backchannelLogoutUrl = getBackchannelLogoutUrl();
	return output;
}

function getCallbackUrl() {
	const baseUrl = nconf.get('url') || '';
	return `${baseUrl.replace(/\/+$/, '')}/auth/authentik/callback`;
}

function getLoginUrl() {
	const baseUrl = nconf.get('url') || '';
	return `${baseUrl.replace(/\/+$/, '')}/auth/authentik`;
}

function getBackchannelLogoutUrl() {
	const baseUrl = nconf.get('url') || '';
	return `${baseUrl.replace(/\/+$/, '')}/auth/authentik/backchannel-logout`;
}

function isLoopbackHttp(url) {
	return url.protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
}

function isBlockedHost(hostname) {
	const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
	if (host === 'localhost' || host === '0.0.0.0' || host === '::' || host === '::1') {
		return true;
	}
	if (net.isIP(host)) {
		return isBlockedIp(host);
	}
	return false;
}

function isBlockedIp(address) {
	const ip = String(address || '').toLowerCase().replace(/^\[|\]$/g, '');
	if (net.isIP(ip) === 4) {
		if (/^127\./.test(ip) || /^169\.254\./.test(ip)) {
			return true;
		}
		if (/^10\./.test(ip) || /^192\.168\./.test(ip)) {
			return true;
		}
		const private172 = ip.match(/^172\.(\d{1,3})\./);
		return !!private172 && parseInt(private172[1], 10) >= 16 && parseInt(private172[1], 10) <= 31;
	}
	if (net.isIP(ip) !== 6) {
		return false;
	}
	if (ip === '::' || ip === '::1' || isIpv6LinkLocal(ip) || ip.startsWith('fc') || ip.startsWith('fd')) {
		return true;
	}
	if (ip.startsWith('::ffff:')) {
		return true;
	}
	return false;
}

function isIpv6LinkLocal(ip) {
	const first = parseInt(ip.split(':')[0], 16);
	return Number.isFinite(first) && first >= 0xfe80 && first <= 0xfebf;
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
		const allowedLoopbackHttp = allowHttp && isLoopbackHttp(url);
		if (url.protocol !== 'https:' && !allowedLoopbackHttp) {
			errors[field] = 'Must be an HTTPS URL';
		} else if (!allowedLoopbackHttp && isBlockedHost(url.hostname)) {
			errors[field] = 'Must not target localhost or private network addresses';
		}
	} catch (err) {
		errors[field] = 'Must be a valid URL';
	}
}

function assertSafeUrl(value, field, { required = true, allowHttp = false } = {}) {
	const errors = {};
	validateUrl(value, field, errors, { required, allowHttp });
	if (errors[field]) {
		const err = new Error(errors[field]);
		err.statusCode = 400;
		err.errors = { [field]: errors[field] };
		throw err;
	}
}

function validate(settings, { requireSecret = false } = {}) {
	const errors = {};
	const allowHttp = settings.allowInsecureCallbackUrlForDevelopment;
	validateUrl(settings.selfServiceProfileUrl, 'selfServiceProfileUrl', errors, { required: false, allowHttp });
	validateUrl(settings.selfServicePasswordUrl, 'selfServicePasswordUrl', errors, { required: false, allowHttp });
	validateUrl(settings.selfServiceMfaUrl, 'selfServiceMfaUrl', errors, { required: false, allowHttp });
	validateUrl(settings.selfServiceSessionsUrl, 'selfServiceSessionsUrl', errors, { required: false, allowHttp });
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
		validateUrl(settings.endSessionEndpoint, 'endSessionEndpoint', errors, {
			required: false,
			allowHttp,
		});
		validateUrl(settings.sessionClearEndpoint, 'sessionClearEndpoint', errors, { required: false, allowHttp });
		if (settings.clearProviderSessionBeforeLogin && !settings.sessionClearEndpoint && !settings.endSessionEndpoint) {
			errors.sessionClearEndpoint = 'Required when no end-session endpoint is configured';
		}
		validateUrl(getCallbackUrl(), 'callbackUrl', errors, { allowHttp });
		if (settings.backchannelLogoutEnabled) {
			validateUrl(getBackchannelLogoutUrl(), 'backchannelLogoutUrl', errors, { allowHttp });
		}
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
	getLoginUrl,
	getBackchannelLogoutUrl,
	assertSafeUrl,
	normalizeSettings,
	publicSettings,
	saveSettings,
	validate,
	validateAuthorizationParameters,
};
