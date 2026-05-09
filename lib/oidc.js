'use strict';

const jose = require('jose');
const openidClient = require('openid-client');
const { requestJson, safeRequestUrl } = require('./http');
const { isBlockedHost } = require('./net-safety');
const { fail } = require('./errors');

const logoutJwksCache = new Map();
const SUPPORTED_SIGNING_ALGORITHMS = new Set(['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']);
const LOGOUT_TOKEN_MAX_AGE_SECONDS = 10 * 60;
const LOGOUT_TOKEN_FUTURE_SKEW_SECONDS = 60;
const ID_TOKEN_MAX_AGE_SECONDS = 10 * 60;
const ID_TOKEN_FUTURE_SKEW_SECONDS = 60;

async function getJwksForDiagnostics(jwksUri) {
	const body = await requestJson(jwksUri);
	return Array.isArray(body.keys) ? body.keys : [];
}

function isSupportedSigningKey(jwk) {
	if (!jwk || !['RSA', 'EC'].includes(jwk.kty)) {
		return false;
	}
	if (jwk.use && jwk.use !== 'sig') {
		return false;
	}
	if (jwk.alg && !SUPPORTED_SIGNING_ALGORITHMS.has(jwk.alg)) {
		return false;
	}
	return true;
}

async function testJwks(jwksUri) {
	if (!jwksUri) {
		throw fail('missing-jwks-uri', 'JWKS URI is required', 'error');
	}
	const keys = await getJwksForDiagnostics(jwksUri);
	const supportedKeys = keys.filter(isSupportedSigningKey);
	if (!supportedKeys.length) {
		throw fail('no-supported-jwks-keys', 'JWKS did not include supported signing keys', 'error');
	}
	return {
		jwksUri,
		keyCount: keys.length,
		supportedSigningKeyCount: supportedKeys.length,
		keyTypes: [...new Set(supportedKeys.map(key => key.kty))].sort(),
		algorithms: [...new Set(supportedKeys.map(key => key.alg).filter(Boolean))].sort(),
		hasKeyIds: supportedKeys.every(key => typeof key.kid === 'string' && key.kid.length > 0),
	};
}

function allowedAlgorithms(settings) {
	if (settings && settings.idTokenSigningAlg) {
		if (!SUPPORTED_SIGNING_ALGORITHMS.has(settings.idTokenSigningAlg)) {
			throw fail('unsupported-id-token-algorithm', 'Configured ID token signing algorithm is unsupported', 'error');
		}
		return [settings.idTokenSigningAlg];
	}
	return ['RS256'];
}

async function exchangeCode(settings, code, stateData, redirectUri) {
	assertSafeProviderUrl(settings.tokenEndpoint, 'tokenEndpoint', {
		allowHttp: !!settings.allowLoopbackProviderEndpointsForDevelopment,
	});
	const currentUrl = new URL(redirectUri);
	currentUrl.searchParams.set('code', code);
	currentUrl.searchParams.set('state', stateData.state || '');
	const checks = {
		expectedState: stateData.state || '',
		expectedNonce: stateData.nonce,
		idTokenExpected: true,
		pkceCodeVerifier: stateData.codeVerifier,
	};
	if (settings.forceProviderLogin) {
		checks.maxAge = 0;
	}
	return await openidClient.authorizationCodeGrant(
		clientConfiguration(settings),
		currentUrl,
		checks
	);
}

function claimsFromTokenSet(settings, tokenSet, stateData = {}) {
	if (!tokenSet || typeof tokenSet.claims !== 'function') {
		throw fail('missing-id-token-claims', 'OIDC provider response did not include validated ID token claims', 'error');
	}
	const claims = tokenSet.claims();
	if (!claims || typeof claims !== 'object') {
		throw fail('missing-id-token-claims', 'OIDC provider response did not include validated ID token claims', 'error');
	}
	validateAuthorizedParty(settings, claims);
	validateIdTokenClaims(settings, claims);
	if (stateData.nonce && claims.nonce !== stateData.nonce) {
		throw fail('invalid-nonce', 'OIDC nonce mismatch', 'error');
	}
	return claims;
}

function validateIdTokenClaims(settings, claims, nowSeconds = Math.floor(Date.now() / 1000)) {
	if (!claims || typeof claims.sub !== 'string' || !claims.sub.trim()) {
		throw fail('invalid-id-token-subject', 'OIDC ID token must contain a non-empty sub', 'error');
	}
	if (!Number.isFinite(claims.exp)) {
		throw fail('invalid-id-token-expiration', 'OIDC ID token must contain exp', 'error');
	}
	if (!Number.isFinite(claims.iat)) {
		throw fail('invalid-id-token-issued-at', 'OIDC ID token must contain iat', 'error');
	}
	if (claims.iat < nowSeconds - ID_TOKEN_MAX_AGE_SECONDS ||
			claims.iat > nowSeconds + ID_TOKEN_FUTURE_SKEW_SECONDS) {
		throw fail('invalid-id-token-issued-at', 'OIDC ID token issued-at is outside the accepted freshness window', 'error');
	}
	if (settings.forceProviderLogin) {
		if (!Number.isFinite(claims.auth_time)) {
			throw fail('invalid-id-token-auth-time', 'OIDC ID token must contain auth_time for fresh login', 'error');
		}
		if (claims.auth_time > nowSeconds + ID_TOKEN_FUTURE_SKEW_SECONDS ||
				claims.auth_time < nowSeconds - ID_TOKEN_MAX_AGE_SECONDS) {
			throw fail('invalid-id-token-auth-time', 'OIDC ID token auth_time is outside the accepted freshness window', 'error');
		}
	}
}

function validateAuthorizedParty(settings, claims) {
	if (claims && Object.prototype.hasOwnProperty.call(claims, 'azp') && claims.azp !== settings.clientId) {
		throw fail('invalid-authorized-party', 'OIDC token authorized party does not match client id', 'error');
	}
	if (!Array.isArray(claims && claims.aud) || claims.aud.length <= 1) {
		return;
	}
	if (!claims.azp) {
		throw fail('invalid-authorized-party', 'OIDC token authorized party does not match client id', 'error');
	}
}

async function verifyLogoutToken(settings, logoutToken) {
	if (!logoutToken) {
		throw fail('missing-logout-token', 'OIDC logout token is required', 'warn');
	}
	if (!settings.jwksUri) {
		throw fail('missing-jwks-uri', 'JWKS URI is required to validate logout token', 'error');
	}
	let result;
	try {
		result = await jose.jwtVerify(logoutToken, logoutJwks(settings), {
			algorithms: allowedAlgorithms(settings),
			audience: settings.clientId,
			issuer: settings.issuer,
			clockTolerance: 60,
		});
	} catch (err) {
		throw fail('invalid-logout-token', `OIDC logout token validation failed: ${err.message}`, 'warn');
	}
	const claims = result.payload;
	validateAuthorizedParty(settings, claims);
	const logoutEvent = claims.events &&
		claims.events['http://schemas.openid.net/event/backchannel-logout'];
	if (!logoutEvent || typeof logoutEvent !== 'object') {
		throw fail('invalid-logout-token-event', 'OIDC logout token is missing the back-channel logout event', 'warn');
	}
	if (Object.prototype.hasOwnProperty.call(claims, 'nonce')) {
		throw fail('invalid-logout-token-nonce', 'OIDC logout token must not contain nonce', 'warn');
	}
	const sub = typeof claims.sub === 'string' && claims.sub.trim() ? claims.sub.trim() : '';
	const sid = typeof claims.sid === 'string' && claims.sid.trim() ? claims.sid.trim() : '';
	if (!sub && !sid) {
		throw fail('invalid-logout-token-subject', 'OIDC logout token must contain sub or sid', 'warn');
	}
	if (typeof claims.iat !== 'number') {
		throw fail('invalid-logout-token-issued-at', 'OIDC logout token must contain iat', 'warn');
	}
	validateLogoutIssuedAt(claims.iat);
	if (!claims.jti) {
		throw fail('invalid-logout-token-id', 'OIDC logout token must contain jti', 'warn');
	}
	return {
		issuer: claims.iss,
		sub,
		sid,
		jti: claims.jti,
		iat: claims.iat,
	};
}

function logoutJwks(settings) {
	const cacheKey = settings.jwksUri;
	if (!logoutJwksCache.has(cacheKey)) {
		logoutJwksCache.set(cacheKey, jose.createRemoteJWKSet(new URL(settings.jwksUri), {
			[jose.customFetch]: safeFetch,
			timeoutDuration: 10000,
			cooldownDuration: 30000,
		}));
	}
	return logoutJwksCache.get(cacheKey);
}

function validateLogoutIssuedAt(iat, nowSeconds = Math.floor(Date.now() / 1000)) {
	if (iat < nowSeconds - LOGOUT_TOKEN_MAX_AGE_SECONDS ||
			iat > nowSeconds + LOGOUT_TOKEN_FUTURE_SKEW_SECONDS) {
		throw fail('invalid-logout-token-issued-at', 'OIDC logout token issued-at is outside the accepted freshness window', 'warn');
	}
}

async function getUserinfo(settings, accessToken, expectedSubject) {
	if (!settings.userinfoEndpoint) {
		return null;
	}
	assertSafeProviderUrl(settings.userinfoEndpoint, 'userinfoEndpoint', {
		allowHttp: !!settings.allowLoopbackProviderEndpointsForDevelopment,
	});
	return await openidClient.fetchUserInfo(
		clientConfiguration(settings),
		accessToken,
		expectedSubject || settings.expectedSubject || undefined
	);
}

function mergeClaims(idClaims, userinfoClaims) {
	if (idClaims && userinfoClaims && idClaims.sub !== userinfoClaims.sub) {
		throw fail('sub-mismatch', 'ID token and userinfo subjects do not match');
	}
	if (idClaims && userinfoClaims) {
		const idEmail = normalizeEmailClaim(idClaims.email);
		const userinfoEmail = normalizeEmailClaim(userinfoClaims.email);
		if (idEmail && userinfoEmail && idEmail !== userinfoEmail) {
			throw fail('email-mismatch', 'ID token and userinfo email claims do not match');
		}
		if (Object.prototype.hasOwnProperty.call(idClaims, 'email_verified') &&
				Object.prototype.hasOwnProperty.call(userinfoClaims, 'email_verified') &&
				idClaims.email_verified !== userinfoClaims.email_verified) {
			throw fail('email-verification-mismatch', 'ID token and userinfo email verification claims do not match');
		}
	}
	return {
		...(idClaims || {}),
		...(userinfoClaims || {}),
		preferred_username: idClaims && idClaims.preferred_username !== undefined ? idClaims.preferred_username : userinfoClaims && userinfoClaims.preferred_username,
		name: idClaims && idClaims.name !== undefined ? idClaims.name : userinfoClaims && userinfoClaims.name,
	};
}

function normalizeEmailClaim(email) {
	return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function normalizeClaims(claims) {
	if (!claims || typeof claims !== 'object') {
		throw fail('missing-claims', 'OIDC claims are missing');
	}
	const sid = typeof claims.sid === 'string' && claims.sid.trim() ? claims.sid.trim() : '';
	return {
		sub: claims.sub,
		email: claims.email,
		email_verified: claims.email_verified,
		preferred_username: claims.preferred_username,
		name: claims.name,
		sid,
	};
}

function providerLogoutUrl(settings, returnTo) {
	const endpoint = settings.sessionClearEndpoint || settings.endSessionEndpoint;
	if (!endpoint) {
		return '';
	}
	const url = new URL(endpoint);
	const returnParameter = settings.sessionClearReturnParameter || 'post_logout_redirect_uri';
	url.searchParams.set(returnParameter, returnTo);
	return url.toString();
}

function providerRelativeUrl(targetUrl, providerUrl) {
	const target = new URL(targetUrl);
	const provider = new URL(providerUrl);
	if (target.origin !== provider.origin) {
		return targetUrl;
	}
	return `${target.pathname}${target.search}`;
}

function authorizationUrl(settings, redirectUri, state, stateData) {
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
	const parameters = {};
	for (const [key, value] of new URLSearchParams(settings.authorizationParameters || '').entries()) {
		if (protectedParams.has(key)) {
			throw fail('invalid-authorization-parameter', `${key} is controlled by the plugin`);
		}
		parameters[key] = value;
	}
	if (settings.forceProviderLogin && !Object.prototype.hasOwnProperty.call(parameters, 'prompt')) {
		parameters.prompt = 'login';
	}
	if (settings.forceProviderLogin && !Object.prototype.hasOwnProperty.call(parameters, 'max_age')) {
		parameters.max_age = '0';
	}
	const url = openidClient.buildAuthorizationUrl(clientConfiguration(settings), {
		...parameters,
		redirect_uri: redirectUri,
		scope: settings.scopes,
		state,
		nonce: stateData.nonce,
		code_challenge: stateData.codeChallenge,
		code_challenge_method: 'S256',
	});
	if (stateData.codeChallenge) {
		url.searchParams.set('code_challenge', stateData.codeChallenge);
		url.searchParams.set('code_challenge_method', 'S256');
	}
	return url.toString();
}

function clientConfiguration(settings) {
	const clientMetadata = {
		client_secret: settings.clientSecret,
	};
	if (settings.tokenEndpointAuthMethod) {
		clientMetadata.token_endpoint_auth_method = settings.tokenEndpointAuthMethod;
	}
	if (settings.idTokenSigningAlg) {
		clientMetadata.id_token_signed_response_alg = settings.idTokenSigningAlg;
	}
	const auth = settings.tokenEndpointAuthMethod === 'client_secret_post' ?
		openidClient.ClientSecretPost(settings.clientSecret) :
		openidClient.ClientSecretBasic(settings.clientSecret);
	const configuration = new openidClient.Configuration({
		issuer: settings.issuer,
		authorization_endpoint: settings.authorizationEndpoint,
		token_endpoint: settings.tokenEndpoint,
		userinfo_endpoint: settings.userinfoEndpoint,
		jwks_uri: settings.jwksUri,
	}, settings.clientId, clientMetadata, settings.clientSecret ? auth : openidClient.None());
	if (!settings.allowLoopbackProviderEndpointsForDevelopment) {
		configuration[openidClient.customFetch] = safeFetch;
	}
	return configuration;
}

async function safeFetch(input, init) {
	const url = input instanceof Request ? input.url : input;
	await safeRequestUrl(url);
	const response = await fetch(input, {
		...(init || {}),
		redirect: 'manual',
	});
	if (response.status >= 300 && response.status < 400) {
		const location = response.headers && response.headers.get ? response.headers.get('location') : '';
		if (location) {
			const redirectTarget = new URL(location, response.url || String(url)).toString();
			await safeRequestUrl(redirectTarget);
		}
		throw fail('provider-redirect-rejected', 'OIDC provider request redirects are not followed automatically', 'error');
	}
	return response;
}

function assertSafeProviderUrl(value, field, { required = true, allowHttp = false } = {}) {
	if (!value) {
		if (!required) {
			return;
		}
		throw fail(`missing-${field}`, `${field} is required`, 'error');
	}
	let url;
	try {
		url = new URL(value);
	} catch (err) {
		throw fail(`invalid-${field}`, `${field} must be a valid URL`, 'error');
	}
	const allowedLoopbackHttp = allowHttp && url.protocol === 'http:' &&
		['localhost', '127.0.0.1', '::1'].includes(url.hostname);
	if (url.protocol !== 'https:' && !allowedLoopbackHttp) {
		throw fail(`unsafe-${field}`, `${field} must be an HTTPS URL`, 'error');
	}
	if (!allowedLoopbackHttp && isBlockedHost(url.hostname)) {
		throw fail(`unsafe-${field}`, `${field} must not target localhost or private network addresses`, 'error');
	}
}

module.exports = {
	authorizationUrl,
	providerLogoutUrl,
	providerRelativeUrl,
	exchangeCode,
	claimsFromTokenSet,
	verifyLogoutToken,
	validateLogoutIssuedAt,
	validateIdTokenClaims,
	validateAuthorizedParty,
	getUserinfo,
	testJwks,
	mergeClaims,
	normalizeClaims,
	clientConfiguration,
	assertSafeProviderUrl,
	allowedAlgorithms,
	safeFetch,
};
