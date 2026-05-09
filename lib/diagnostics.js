'use strict';

const db = require.main.require('./src/database');
const { redactString, sanitizeErrorForLog } = require('./redact');

const LAST_FAILURE_KEY = 'authentik:diagnostics:lastFailure';
const LAST_LOGOUT_KEY = 'authentik:diagnostics:lastLogout';
const LAST_AUTHORIZATION_KEY = 'authentik:diagnostics:lastAuthorization';

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
	const sanitized = sanitizeErrorForLog(err);
	return {
		code: sanitized.code,
		message: sanitized.message,
		level: sanitized.level,
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
		sessionsBefore: Number.isFinite(event.sessionsBefore) ? event.sessionsBefore : -1,
		sessionsAfter: Number.isFinite(event.sessionsAfter) ? event.sessionsAfter : -1,
		code: event.code || '',
		message: redactString(event.message || ''),
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

async function recordAuthorizationStart(event) {
	const authorization = {
		at: Date.now(),
		stage: event.stage || 'authorization',
		clearProviderSessionBeforeLogin: !!event.clearProviderSessionBeforeLogin,
		forceProviderLogin: !!event.forceProviderLogin,
		hasEndSessionEndpoint: !!event.hasEndSessionEndpoint,
		sessionClearEndpointOverride: !!event.sessionClearEndpointOverride,
		sessionClearReturnParameter: event.sessionClearReturnParameter || '',
		authorizationParameters: event.authorizationParameters || '',
		redirectTarget: sanitizeRedirectTarget(event.redirectTarget),
		returnTo: sanitizeRedirectTarget(event.returnTo),
		returnToWasProviderRelative: !!event.returnToWasProviderRelative,
	};
	if (typeof db.setObject === 'function') {
		await db.setObject(LAST_AUTHORIZATION_KEY, authorization);
	}
	return deserializeAuthorizationStart(authorization);
}

async function getLastAuthorizationStart() {
	if (typeof db.getObject !== 'function') {
		return null;
	}
	return deserializeAuthorizationStart(await db.getObject(LAST_AUTHORIZATION_KEY));
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
		sessionsBefore: event.sessionsBefore !== undefined ? parseInt(event.sessionsBefore, 10) : -1,
		sessionsAfter: event.sessionsAfter !== undefined ? parseInt(event.sessionsAfter, 10) : -1,
		statusCode: event.statusCode ? parseInt(event.statusCode, 10) : 0,
	};
}

function sanitizeRedirectTarget(value) {
	if (!value || typeof value !== 'string') {
		return '';
	}
	try {
		const relative = value.startsWith('/');
		const url = new URL(value, relative ? 'https://provider.local' : undefined);
		const safeParams = new URLSearchParams();
		[
			'client_id',
			'code_challenge_method',
			'max_age',
			'post_logout_redirect_uri',
			'prompt',
			'redirect_uri',
			'response_type',
			'scope',
		].forEach((key) => {
			if (url.searchParams.has(key)) {
				safeParams.set(key, url.searchParams.get(key));
			}
		});
		const sanitizedPath = `${url.pathname}${safeParams.toString() ? `?${safeParams.toString()}` : ''}`;
		return relative ? sanitizedPath : `${url.origin}${sanitizedPath}`;
	} catch (err) {
		return '';
	}
}

function deserializeAuthorizationStart(event) {
	if (!event || !event.at) {
		return null;
	}
	return {
		...event,
		at: parseInt(event.at, 10),
		clearProviderSessionBeforeLogin: event.clearProviderSessionBeforeLogin === true ||
			event.clearProviderSessionBeforeLogin === 'true' ||
			event.clearProviderSessionBeforeLogin === 1 ||
			event.clearProviderSessionBeforeLogin === '1',
		forceProviderLogin: event.forceProviderLogin === true ||
			event.forceProviderLogin === 'true' ||
			event.forceProviderLogin === 1 ||
			event.forceProviderLogin === '1',
		hasEndSessionEndpoint: event.hasEndSessionEndpoint === true ||
			event.hasEndSessionEndpoint === 'true' ||
			event.hasEndSessionEndpoint === 1 ||
			event.hasEndSessionEndpoint === '1',
		sessionClearEndpointOverride: event.sessionClearEndpointOverride === true ||
			event.sessionClearEndpointOverride === 'true' ||
			event.sessionClearEndpointOverride === 1 ||
			event.sessionClearEndpointOverride === '1',
		returnToWasProviderRelative: event.returnToWasProviderRelative === true ||
			event.returnToWasProviderRelative === 'true' ||
			event.returnToWasProviderRelative === 1 ||
			event.returnToWasProviderRelative === '1',
	};
}

module.exports = {
	LAST_FAILURE_KEY,
	LAST_LOGOUT_KEY,
	LAST_AUTHORIZATION_KEY,
	claimMeta,
	deserializeAuthorizationStart,
	deserializeFailure,
	deserializeLogoutEvent,
	getLastAuthorizationStart,
	getLastFailure,
	getLastLogoutEvent,
	recordAuthorizationStart,
	recordFailure,
	recordLogoutEvent,
};
