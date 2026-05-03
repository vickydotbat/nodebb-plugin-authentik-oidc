'use strict';

const jwt = require('jsonwebtoken');
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
	const keys = await getJwks(jwksUri);
	const key = keys.find(candidate => candidate.kid === decoded.header.kid) ||
		(decoded.header.kid ? null : keys.find(candidate => candidate.kty === 'RSA'));
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

async function verifyIdToken(settings, idToken, nonce) {
	if (!idToken) {
		return null;
	}
	if (!settings.jwksUri) {
		throw fail('missing-jwks-uri', 'JWKS URI is required to validate ID token', 'error');
	}
	const key = await getSigningKey(settings.jwksUri, idToken);
	const claims = jwt.verify(idToken, key, {
		algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
		audience: settings.clientId,
		issuer: settings.issuer,
		clockTolerance: 60,
	});
	if (claims.nonce !== nonce) {
		throw fail('invalid-nonce', 'OIDC nonce mismatch', 'error');
	}
	return claims;
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
	return {
		...(idClaims || {}),
		...(userinfoClaims || {}),
	};
}

function normalizeClaims(claims) {
	if (!claims || typeof claims !== 'object') {
		throw fail('missing-claims', 'OIDC claims are missing');
	}
	return {
		sub: claims.sub,
		email: claims.email,
		email_verified: claims.email_verified,
		preferred_username: claims.preferred_username,
		name: claims.name,
	};
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
	exchangeCode,
	verifyIdToken,
	getUserinfo,
	testJwks,
	mergeClaims,
	normalizeClaims,
};
