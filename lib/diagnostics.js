'use strict';

const db = require.main.require('./src/database');

const LAST_FAILURE_KEY = 'authentik:diagnostics:lastFailure';

function claimMeta(claims) {
	const source = claims && typeof claims === 'object' ? claims : {};
	return {
		hasSub: typeof source.sub === 'string' && source.sub.length > 0,
		hasEmail: typeof source.email === 'string' && source.email.length > 0,
		emailVerifiedType: Object.prototype.hasOwnProperty.call(source, 'email_verified') ?
			typeof source.email_verified :
			'missing',
		emailVerifiedValue: typeof source.email_verified === 'boolean' ? source.email_verified : null,
		hasPreferredUsername: typeof source.preferred_username === 'string' && source.preferred_username.length > 0,
		hasName: typeof source.name === 'string' && source.name.length > 0,
		issuer: typeof source.iss === 'string' ? source.iss : '',
		audienceType: Object.prototype.hasOwnProperty.call(source, 'aud') ? typeof source.aud : 'missing',
	};
}

function normalizeError(err) {
	return {
		code: err && err.code ? err.code : 'unexpected-error',
		message: err && err.message ? err.message : 'Unexpected OIDC login failure',
		level: err && err.level ? err.level : 'error',
	};
}

async function recordFailure({ err, stage, settings, idClaims, userinfoClaims, mergedClaims }) {
	const failure = {
		at: Date.now(),
		stage: stage || 'callback',
		...normalizeError(err),
		configuredIssuer: settings && settings.issuer ? settings.issuer : '',
		userinfoUsed: !!userinfoClaims,
		idTokenClaims: JSON.stringify(claimMeta(idClaims)),
		userinfoClaims: JSON.stringify(claimMeta(userinfoClaims)),
		mergedClaims: JSON.stringify(claimMeta(mergedClaims)),
	};
	if (typeof db.setObject === 'function') {
		await db.setObject(LAST_FAILURE_KEY, failure);
	}
	return deserializeFailure(failure);
}

async function getLastFailure() {
	if (typeof db.getObject !== 'function') {
		return null;
	}
	return deserializeFailure(await db.getObject(LAST_FAILURE_KEY));
}

function parseJsonField(value) {
	if (!value) {
		return claimMeta(null);
	}
	if (typeof value === 'object') {
		return value;
	}
	try {
		return JSON.parse(value);
	} catch (err) {
		return claimMeta(null);
	}
}

function deserializeFailure(failure) {
	if (!failure || !failure.at) {
		return null;
	}
	return {
		...failure,
		at: parseInt(failure.at, 10),
		userinfoUsed: failure.userinfoUsed === true || failure.userinfoUsed === 'true' || failure.userinfoUsed === 1 || failure.userinfoUsed === '1',
		idTokenClaims: parseJsonField(failure.idTokenClaims),
		userinfoClaims: parseJsonField(failure.userinfoClaims),
		mergedClaims: parseJsonField(failure.mergedClaims),
	};
}

module.exports = {
	LAST_FAILURE_KEY,
	claimMeta,
	deserializeFailure,
	getLastFailure,
	recordFailure,
};
