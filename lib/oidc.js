'use strict';

const jwt = require('jsonwebtoken');
const { requestJson } = require('./http');
const { trimIssuer } = require('./discovery');
const { fail } = require('./errors');

const jwksCache = new Map();

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
		issuer: trimIssuer(settings.issuer),
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
	mergeClaims,
	normalizeClaims,
};
