'use strict';

const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');
const { requestJson } = require('./http');
const { fail } = require('./errors');

const jwksCache = new Map();
const SUPPORTED_SIGNING_ALGORITHMS = new Set(['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']);

function jwkToKeyObject(jwk) {
	if (!['RSA', 'EC'].includes(jwk.kty)) {
		throw new Error('Unsupported JWK');
	}
	return require('node:crypto').createPublicKey({ key: jwk, format: 'jwk' });
}

async function getJwks(jwksUri) {
	const cached = jwksCache.get(jwksUri);
	if (cached && cached.expiresAt > Date.now()) {
		return cached.keys;
	}
	const body = await requestJson(jwksUri);
	const keys = Array.isArray(body.keys) ? body.keys : [];
	jwksCache.set(jwksUri, {
		keys,
		expiresAt: Date.now() + (60 * 60 * 1000),
	});
	return keys;
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
	const keys = await getJwks(jwksUri);
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

async function getSigningKey(jwksUri, token) {
	const decoded = jwt.decode(token, { complete: true });
	if (!decoded || !decoded.header) {
		throw fail('invalid-id-token', 'Invalid ID token', 'error');
	}
	if (!SUPPORTED_SIGNING_ALGORITHMS.has(decoded.header.alg)) {
		throw fail('unsupported-id-token-algorithm', 'ID token used an unsupported signing algorithm', 'error');
	}
	const keys = await getJwks(jwksUri);
	const candidates = keys.filter((candidate) => {
		if (!isSupportedSigningKey(candidate)) {
			return false;
		}
		if (candidate.alg && candidate.alg !== decoded.header.alg) {
			return false;
		}
		return decoded.header.kid ? candidate.kid === decoded.header.kid : candidate.kty === 'RSA';
	});
	const key = candidates[0] || null;
	if (!key) {
		throw fail('missing-signing-key', 'Unable to find OIDC signing key', 'error');
	}
	return jwkToKeyObject(key);
}

async function exchangeCode(settings, code, stateData, redirectUri) {
	const body = new URLSearchParams();
	body.set('grant_type', 'authorization_code');
	body.set('code', code);
	body.set('redirect_uri', redirectUri);
	body.set('client_id', settings.clientId);
	if (settings.clientSecret) {
		body.set('client_secret', settings.clientSecret);
	}
	if (stateData.codeVerifier) {
		body.set('code_verifier', stateData.codeVerifier);
	}
	return await requestJson(settings.tokenEndpoint, {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded',
		},
		body,
	});
}

async function verifyIdToken(settings, idToken, nonce, tokenValues = {}) {
	if (!idToken) {
		return null;
	}
	if (!settings.jwksUri) {
		throw fail('missing-jwks-uri', 'JWKS URI is required to validate ID token', 'error');
	}
	const decoded = jwt.decode(idToken, { complete: true });
	if (!decoded || !decoded.header) {
		throw fail('invalid-id-token', 'Invalid ID token', 'error');
	}
	const key = await getSigningKey(settings.jwksUri, idToken);
	const claims = jwt.verify(idToken, key, {
		algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
		audience: settings.clientId,
		issuer: settings.issuer,
		clockTolerance: 60,
	});
	validateAuthorizedParty(settings, claims);
	if (claims.nonce !== nonce) {
		throw fail('invalid-nonce', 'OIDC nonce mismatch', 'error');
	}
	validateTokenHash(claims.at_hash, tokenValues.accessToken, 'access token hash', decoded.header.alg);
	validateTokenHash(claims.c_hash, tokenValues.code, 'authorization code hash', decoded.header.alg);
	return claims;
}

function validateTokenHash(expectedHash, value, label, algorithm) {
	if (!expectedHash) {
		return;
	}
	if (!value) {
		throw fail('missing-token-hash-input', `OIDC ${label} is present but the source value is missing`, 'error');
	}
	if (oidcHash(value, algorithm) !== expectedHash) {
		throw fail('invalid-token-hash', `OIDC ${label} does not match`, 'error');
	}
}

function oidcHash(value, algorithm = 'RS256') {
	const digestAlgorithm = algorithm.includes('384') ? 'sha384' :
		algorithm.includes('512') ? 'sha512' :
			'sha256';
	const digest = crypto.createHash(digestAlgorithm).update(value).digest();
	return digest.subarray(0, digest.length / 2).toString('base64url');
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
	const key = await getSigningKey(settings.jwksUri, logoutToken);
	const claims = jwt.verify(logoutToken, key, {
		algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
		audience: settings.clientId,
		issuer: settings.issuer,
		clockTolerance: 60,
	});
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
	if (!claims.jti) {
		throw fail('invalid-logout-token-id', 'OIDC logout token must contain jti', 'warn');
	}
	return {
		sub,
		sid,
		jti: claims.jti,
		iat: claims.iat,
	};
}

async function getUserinfo(settings, accessToken) {
	if (!settings.userinfoEndpoint) {
		return null;
	}
	return await requestJson(settings.userinfoEndpoint, {
		headers: {
			authorization: `Bearer ${accessToken}`,
		},
	});
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
	const url = new URL(settings.authorizationEndpoint);
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
	for (const [key, value] of new URLSearchParams(settings.authorizationParameters || '').entries()) {
		if (protectedParams.has(key)) {
			throw fail('invalid-authorization-parameter', `${key} is controlled by the plugin`);
		}
		url.searchParams.append(key, value);
	}
	if (settings.forceProviderLogin && !url.searchParams.has('prompt')) {
		url.searchParams.set('prompt', 'login');
	}
	if (settings.forceProviderLogin && !url.searchParams.has('max_age')) {
		url.searchParams.set('max_age', '0');
	}
	url.searchParams.set('response_type', 'code');
	url.searchParams.set('client_id', settings.clientId);
	url.searchParams.set('redirect_uri', redirectUri);
	url.searchParams.set('scope', settings.scopes);
	url.searchParams.set('state', state);
	url.searchParams.set('nonce', stateData.nonce);
	if (stateData.codeChallenge) {
		url.searchParams.set('code_challenge', stateData.codeChallenge);
		url.searchParams.set('code_challenge_method', 'S256');
	}
	return url.toString();
}

module.exports = {
	authorizationUrl,
	providerLogoutUrl,
	providerRelativeUrl,
	exchangeCode,
	verifyIdToken,
	verifyLogoutToken,
	validateAuthorizedParty,
	oidcHash,
	getUserinfo,
	testJwks,
	mergeClaims,
	normalizeClaims,
};
