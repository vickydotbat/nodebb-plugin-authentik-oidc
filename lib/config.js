'use strict';

const nconf = require.main.require('nconf');
const meta = require.main.require('./src/meta');
const { z } = require('zod');
const { isBlockedHost } = require('./net-safety');

const SETTINGS_KEY = 'authentik-oidc';
const SECRET_PLACEHOLDER = '********';
const ACCOUNT_LINKING_POLICIES = ['no_auto_link', 'trusted_email_auto_link'];
const SESSION_CLEAR_RETURN_PARAMETERS = ['post_logout_redirect_uri', 'next'];
const TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post'];
const USERNAME_COLLISION_POLICIES = ['unique', 'reject'];
const SUPPORTED_SIGNING_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];
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
	allowLoopbackProviderEndpointsForDevelopment: false,
	redirectRegisterToLogin: true,
	allowAccountCreation: true,
	accountLinkingPolicy: 'no_auto_link',
	tokenEndpointAuthMethod: 'client_secret_basic',
	idTokenSigningAlg: 'RS256',
	usernameCollisionPolicy: 'unique',
	syncFullnameOnLogin: false,
};

function booleanValue(value) {
	return value === true || value === 'true' || value === 1 || value === '1' || value === 'on';
}

function trimString(value) {
	return typeof value === 'string' ? value.trim() : '';
}

function booleanField(defaultValue) {
	return z.preprocess((value) => {
		if (value === undefined) {
			return defaultValue;
		}
		return booleanValue(value);
	}, z.boolean());
}

function stringField(defaultValue = '') {
	return z.preprocess((value) => {
		if (value === undefined) {
			return defaultValue;
		}
		return trimString(value);
	}, z.string());
}

function enumField(values, defaultValue) {
	return z.preprocess((value) => {
		if (value === undefined) {
			return defaultValue;
		}
		return trimString(value);
	}, z.enum(values).catch(defaultValue));
}

const NormalizedSettingsSchema = z.object({
	enabled: booleanField(DEFAULTS.enabled),
	clientId: stringField(DEFAULTS.clientId),
	clientSecret: stringField(DEFAULTS.clientSecret),
	issuer: stringField(DEFAULTS.issuer),
	authorizationEndpoint: stringField(DEFAULTS.authorizationEndpoint),
	tokenEndpoint: stringField(DEFAULTS.tokenEndpoint),
	userinfoEndpoint: stringField(DEFAULTS.userinfoEndpoint),
	jwksUri: stringField(DEFAULTS.jwksUri),
	endSessionEndpoint: stringField(DEFAULTS.endSessionEndpoint),
	scopes: stringField(DEFAULTS.scopes),
	authorizationParameters: stringField(DEFAULTS.authorizationParameters),
	forceProviderLogin: booleanField(DEFAULTS.forceProviderLogin),
	clearProviderSessionBeforeLogin: booleanField(DEFAULTS.clearProviderSessionBeforeLogin),
	sessionClearEndpoint: stringField(DEFAULTS.sessionClearEndpoint),
	sessionClearReturnParameter: enumField(SESSION_CLEAR_RETURN_PARAMETERS, DEFAULTS.sessionClearReturnParameter),
	selfServiceProfileUrl: stringField(DEFAULTS.selfServiceProfileUrl),
	selfServicePasswordUrl: stringField(DEFAULTS.selfServicePasswordUrl),
	selfServiceMfaUrl: stringField(DEFAULTS.selfServiceMfaUrl),
	selfServiceSessionsUrl: stringField(DEFAULTS.selfServiceSessionsUrl),
	backchannelLogoutEnabled: booleanField(DEFAULTS.backchannelLogoutEnabled),
	displayName: stringField(DEFAULTS.displayName),
	allowInsecureCallbackUrlForDevelopment: booleanField(DEFAULTS.allowInsecureCallbackUrlForDevelopment),
	allowLoopbackProviderEndpointsForDevelopment: booleanField(DEFAULTS.allowLoopbackProviderEndpointsForDevelopment),
	redirectRegisterToLogin: booleanField(DEFAULTS.redirectRegisterToLogin),
	allowAccountCreation: booleanField(DEFAULTS.allowAccountCreation),
	accountLinkingPolicy: enumField(ACCOUNT_LINKING_POLICIES, DEFAULTS.accountLinkingPolicy),
	tokenEndpointAuthMethod: enumField(TOKEN_ENDPOINT_AUTH_METHODS, DEFAULTS.tokenEndpointAuthMethod),
	idTokenSigningAlg: stringField(DEFAULTS.idTokenSigningAlg),
	usernameCollisionPolicy: enumField(USERNAME_COLLISION_POLICIES, DEFAULTS.usernameCollisionPolicy),
	syncFullnameOnLogin: booleanField(DEFAULTS.syncFullnameOnLogin),
}).strip();

function normalizeSettings(raw) {
	return NormalizedSettingsSchema.parse({ ...DEFAULTS, ...(raw || {}) });
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
	const hostname = url.hostname.replace(/^\[|\]$/g, '');
	return url.protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(hostname);
}

function getSafeUrlError(value, { required = true, allowHttp = false } = {}) {
	if (!value) {
		if (required) {
			return 'Required';
		}
		return '';
	}
	try {
		const url = new URL(value);
		const allowedLoopbackHttp = allowHttp && isLoopbackHttp(url);
		if (url.protocol !== 'https:' && !allowedLoopbackHttp) {
			return 'Must be an HTTPS URL';
		} else if (!allowedLoopbackHttp && isBlockedHost(url.hostname)) {
			return 'Must not target localhost or private network addresses';
		}
	} catch (err) {
		return 'Must be a valid URL';
	}
	return '';
}

function validateUrl(value, field, errors, { required = true, allowHttp = false } = {}) {
	const message = getSafeUrlError(value, { required, allowHttp });
	if (message) {
		errors[field] = message;
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
	const parsed = createValidationSchema({ requireSecret }).safeParse(settings);
	if (parsed.success) {
		return {};
	}
	return zodFieldErrors(parsed.error);
}

function createValidationSchema({ requireSecret = false } = {}) {
	return NormalizedSettingsSchema.superRefine((settings, ctx) => {
		const allowCallbackHttp = settings.allowInsecureCallbackUrlForDevelopment;
		const allowProviderHttp = settings.allowLoopbackProviderEndpointsForDevelopment;

		addUrlIssue(ctx, settings.selfServiceProfileUrl, 'selfServiceProfileUrl', { required: false, allowHttp: allowProviderHttp });
		addUrlIssue(ctx, settings.selfServicePasswordUrl, 'selfServicePasswordUrl', { required: false, allowHttp: allowProviderHttp });
		addUrlIssue(ctx, settings.selfServiceMfaUrl, 'selfServiceMfaUrl', { required: false, allowHttp: allowProviderHttp });
		addUrlIssue(ctx, settings.selfServiceSessionsUrl, 'selfServiceSessionsUrl', { required: false, allowHttp: allowProviderHttp });
		addSupportedSigningAlgorithmIssue(ctx, settings);

		if (!settings.enabled) {
			return;
		}
		if (!settings.clientId) {
			addFieldIssue(ctx, 'clientId', 'Required');
		}
		if (requireSecret && !settings.clientSecret) {
			addFieldIssue(ctx, 'clientSecret', 'Required');
		}
		const scopes = settings.scopes.split(/\s+/).filter(Boolean);
		if (!scopes.includes('openid')) {
			addFieldIssue(ctx, 'scopes', 'Must include openid');
		}
		if (scopes.includes('offline_access')) {
			addFieldIssue(ctx, 'scopes', 'Must not request offline_access');
		}
		addAuthorizationParametersIssue(ctx, settings.authorizationParameters);
		addUrlIssue(ctx, settings.issuer, 'issuer', { allowHttp: allowProviderHttp });
		addUrlIssue(ctx, settings.authorizationEndpoint, 'authorizationEndpoint', { allowHttp: allowProviderHttp });
		addUrlIssue(ctx, settings.tokenEndpoint, 'tokenEndpoint', { allowHttp: allowProviderHttp });
		addUrlIssue(ctx, settings.userinfoEndpoint, 'userinfoEndpoint', { allowHttp: allowProviderHttp });
		addUrlIssue(ctx, settings.jwksUri, 'jwksUri', { allowHttp: allowProviderHttp });
		addUrlIssue(ctx, settings.endSessionEndpoint, 'endSessionEndpoint', {
			required: false,
			allowHttp: allowProviderHttp,
		});
		addUrlIssue(ctx, settings.sessionClearEndpoint, 'sessionClearEndpoint', { required: false, allowHttp: allowProviderHttp });
		if (settings.clearProviderSessionBeforeLogin && !settings.sessionClearEndpoint && !settings.endSessionEndpoint) {
			addFieldIssue(ctx, 'sessionClearEndpoint', 'Required when no end-session endpoint is configured');
		}
		addUrlIssue(ctx, getCallbackUrl(), 'callbackUrl', { allowHttp: allowCallbackHttp });
		if (settings.backchannelLogoutEnabled) {
			addUrlIssue(ctx, getBackchannelLogoutUrl(), 'backchannelLogoutUrl', { allowHttp: allowCallbackHttp });
		}
	});
}

function addUrlIssue(ctx, value, field, options) {
	const message = getSafeUrlError(value, options);
	if (message) {
		addFieldIssue(ctx, field, message);
	}
}

function addSupportedSigningAlgorithmIssue(ctx, settings) {
	if (settings.idTokenSigningAlg && !SUPPORTED_SIGNING_ALGORITHMS.includes(settings.idTokenSigningAlg)) {
		addFieldIssue(ctx, 'idTokenSigningAlg', 'Must be a supported asymmetric signing algorithm');
	}
}

function addAuthorizationParametersIssue(ctx, value) {
	const message = getAuthorizationParametersError(value);
	if (message) {
		addFieldIssue(ctx, 'authorizationParameters', message);
	}
}

function addFieldIssue(ctx, field, message) {
	ctx.addIssue({
		code: 'custom',
		path: [field],
		message,
	});
}

function zodFieldErrors(error) {
	const errors = {};
	for (const issue of error.issues) {
		const field = issue.path[0];
		if (field && !errors[field]) {
			errors[field] = issue.message;
		}
	}
	return errors;
}

function validateAuthorizationParameters(value, errors) {
	const message = getAuthorizationParametersError(value);
	if (message) {
		errors.authorizationParameters = message;
	}
}

function getAuthorizationParametersError(value) {
	if (!value) {
		return '';
	}
	let params;
	try {
		params = new URLSearchParams(value);
	} catch (err) {
		return 'Must use query string format, for example prompt=login';
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
			return `${key} is controlled by the plugin`;
		}
	}
	return '';
}

async function getSettings() {
	const settings = normalizeSettings(await meta.settings.get(SETTINGS_KEY));
	if (process.env.AUTHENTIK_OIDC_CLIENT_SECRET) {
		settings.clientSecret = process.env.AUTHENTIK_OIDC_CLIENT_SECRET;
	}
	return settings;
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
