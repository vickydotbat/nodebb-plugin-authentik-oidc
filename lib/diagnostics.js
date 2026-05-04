'use strict';

const db = require.main.require('./src/database');

const LAST_FAILURE_KEY = 'authentik:diagnostics:lastFailure';
const LAST_LOGOUT_KEY = 'authentik:diagnostics:lastLogout';

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

async function recordLogoutEvent(event) {
	const logoutEvent = {
		at: Date.now(),
		stage: event.stage || 'received',
		outcome: event.outcome || 'unknown',
		enabled: !!event.enabled,
		hasLogoutToken: !!event.hasLogoutToken,
		tokenValidated: !!event.tokenValidated,
		hasSub: !!event.hasSub,
		hasSid: !!event.hasSid,
		uid: event.uid ? parseInt(event.uid, 10) : 0,
		source: event.source || '',
		code: event.code || '',
		message: event.message || '',
		statusCode: event.statusCode ? parseInt(event.statusCode, 10) : 0,
	};
	if (typeof db.setObject === 'function') {
		await db.setObject(LAST_LOGOUT_KEY, logoutEvent);
	}
	return deserializeLogoutEvent(logoutEvent);
}

async function getLastLogoutEvent() {
	if (typeof db.getObject !== 'function') {
		return null;
	}
	return deserializeLogoutEvent(await db.getObject(LAST_LOGOUT_KEY));
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

function deserializeLogoutEvent(event) {
	if (!event || !event.at) {
		return null;
	}
	return {
		...event,
		at: parseInt(event.at, 10),
		enabled: event.enabled === true || event.enabled === 'true' || event.enabled === 1 || event.enabled === '1',
		hasLogoutToken: event.hasLogoutToken === true || event.hasLogoutToken === 'true' || event.hasLogoutToken === 1 || event.hasLogoutToken === '1',
		tokenValidated: event.tokenValidated === true || event.tokenValidated === 'true' || event.tokenValidated === 1 || event.tokenValidated === '1',
		hasSub: event.hasSub === true || event.hasSub === 'true' || event.hasSub === 1 || event.hasSub === '1',
		hasSid: event.hasSid === true || event.hasSid === 'true' || event.hasSid === 1 || event.hasSid === '1',
		uid: event.uid ? parseInt(event.uid, 10) : 0,
		statusCode: event.statusCode ? parseInt(event.statusCode, 10) : 0,
	};
}

module.exports = {
	LAST_FAILURE_KEY,
	LAST_LOGOUT_KEY,
	claimMeta,
	deserializeFailure,
	deserializeLogoutEvent,
	getLastFailure,
	getLastLogoutEvent,
	recordFailure,
	recordLogoutEvent,
};
