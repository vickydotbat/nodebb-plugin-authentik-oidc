'use strict';

const openidClient = require('openid-client');
const { isBlockedHost } = require('./net-safety');
const { safeFetch } = require('./oidc');

function trimIssuer(issuer) {
	return String(issuer || '').replace(/\/+$/, '');
}

function issuersMatch(configuredIssuer, discoveredIssuer) {
	return String(configuredIssuer || '') === String(discoveredIssuer || '');
}

function discoveryUrl(issuer) {
	return `${trimIssuer(issuer)}/.well-known/openid-configuration`;
}

async function discover(issuer, options = {}) {
	const discoveryOptions = {};
	if (options.allowLoopbackProviderEndpointsForDevelopment) {
		discoveryOptions.execute = [openidClient.allowInsecureRequests];
	} else {
		discoveryOptions[openidClient.customFetch] = safeFetch;
	}
	const configuration = await openidClient.discovery(
		new URL(issuer),
		options.clientId || 'nodebb-plugin-authentik-oidc-discovery',
		{},
		openidClient.None(),
		discoveryOptions
	);
	const metadata = configuration.serverMetadata();
	if (!issuersMatch(issuer, metadata.issuer)) {
		const err = new Error('Discovery issuer does not match configured issuer');
		err.statusCode = 400;
		throw err;
	}
	validateMetadata(metadata, options);
	return {
		issuer: metadata.issuer,
		authorizationEndpoint: metadata.authorization_endpoint || '',
		tokenEndpoint: metadata.token_endpoint || '',
		userinfoEndpoint: metadata.userinfo_endpoint || '',
		jwksUri: metadata.jwks_uri || '',
		endSessionEndpoint: metadata.end_session_endpoint || '',
		scopesSupported: metadata.scopes_supported || [],
		responseTypesSupported: metadata.response_types_supported || [],
		tokenEndpointAuthMethodsSupported: metadata.token_endpoint_auth_methods_supported || [],
	};
}

function validateMetadata(metadata, options = {}) {
	const allowHttp = !!options.allowLoopbackProviderEndpointsForDevelopment;
	[
		['authorization_endpoint', 'authorizationEndpoint', true],
		['token_endpoint', 'tokenEndpoint', true],
		['jwks_uri', 'jwksUri', true],
		['userinfo_endpoint', 'userinfoEndpoint', false],
		['end_session_endpoint', 'endSessionEndpoint', false],
	].forEach(([metadataKey, field, required]) => {
		assertSafeMetadataUrl(metadata && metadata[metadataKey], field, { required, allowHttp });
	});
}

function assertSafeMetadataUrl(value, field, { required = true, allowHttp = false } = {}) {
	if (!value) {
		if (!required) {
			return;
		}
		throw metadataError(field, 'Required');
	}
	let url;
	try {
		url = new URL(value);
	} catch (err) {
		throw metadataError(field, 'Must be a valid URL');
	}
	const allowedLoopbackHttp = allowHttp && url.protocol === 'http:' &&
		['localhost', '127.0.0.1', '::1'].includes(url.hostname);
	if (url.protocol !== 'https:' && !allowedLoopbackHttp) {
		throw metadataError(field, 'Must be an HTTPS URL');
	}
	if (!allowedLoopbackHttp && isBlockedHost(url.hostname)) {
		throw metadataError(field, 'Must not target localhost or private network addresses');
	}
}

function metadataError(field, message) {
	const err = new Error(message);
	err.statusCode = 400;
	err.errors = { [field]: message };
	return err;
}

module.exports = { discover, discoveryUrl, issuersMatch, trimIssuer, validateMetadata, assertSafeMetadataUrl };
