'use strict';

const { requestJson } = require('./http');

function trimIssuer(issuer) {
	return String(issuer || '').replace(/\/+$/, '');
}

function discoveryUrl(issuer) {
	return `${trimIssuer(issuer)}/.well-known/openid-configuration`;
}

async function discover(issuer) {
	const normalizedIssuer = trimIssuer(issuer);
	const metadata = await requestJson(discoveryUrl(normalizedIssuer));
	if (trimIssuer(metadata.issuer) !== normalizedIssuer) {
		const err = new Error('Discovery issuer does not match configured issuer');
		err.statusCode = 400;
		throw err;
	}
	return {
		issuer: trimIssuer(metadata.issuer),
		authorizationEndpoint: metadata.authorization_endpoint || '',
		tokenEndpoint: metadata.token_endpoint || '',
		userinfoEndpoint: metadata.userinfo_endpoint || '',
		jwksUri: metadata.jwks_uri || '',
		scopesSupported: metadata.scopes_supported || [],
		responseTypesSupported: metadata.response_types_supported || [],
		tokenEndpointAuthMethodsSupported: metadata.token_endpoint_auth_methods_supported || [],
	};
}

module.exports = { discover, discoveryUrl, trimIssuer };
