'use strict';

const Strategy = require('passport-strategy');
const util = require('node:util');

const identity = require('./identity');
const diagnostics = require('./diagnostics');
const { fail } = require('./errors');
const logger = require('./logger');
const oidc = require('./oidc');
const stateStore = require('./state');
const profileSync = require('./sync');

const SESSION_CLEAR_MARKER = 'authentikOidcProviderSessionCleared';

function AuthentikOidcStrategy(options) {
	Strategy.call(this);
	this.name = 'authentik';
	this.config = options.config;
}

util.inherits(AuthentikOidcStrategy, Strategy);

AuthentikOidcStrategy.prototype.authenticate = async function (req, options) {
	let settings;
	let idClaims = null;
	let userinfoClaims = null;
	let mergedClaims = null;
	try {
		settings = await this.config.getSettings();
		const redirectUri = this.config.getCallbackUrl();

		if (req.query.error) {
			logger.warn('provider returned oidc error', { error: req.query.error });
			throw fail('provider-error', 'OIDC provider rejected the authentication request', 'error');
		}

		const callbackParams = parseCallbackParams(req, redirectUri);
		if (!callbackParams.isCallback) {
				const stateData = await stateStore.create(req);
			const authorizationUrl = oidc.authorizationUrl(settings, redirectUri, stateData.state, stateData);
			if (settings.clearProviderSessionBeforeLogin && !consumeProviderSessionCleared(req)) {
				const returnTo = settings.sessionClearReturnParameter === 'next' ?
					oidc.providerRelativeUrl(authorizationUrl, settings.sessionClearEndpoint || settings.endSessionEndpoint) :
					this.config.getLoginUrl();
				const logoutUrl = oidc.providerLogoutUrl(settings, returnTo);
				if (logoutUrl) {
					markProviderSessionClearPending(req);
					await diagnostics.recordAuthorizationStart({
						stage: 'provider-session-clear',
						clearProviderSessionBeforeLogin: settings.clearProviderSessionBeforeLogin,
						forceProviderLogin: settings.forceProviderLogin,
						hasEndSessionEndpoint: !!settings.endSessionEndpoint,
						sessionClearEndpointOverride: !!settings.sessionClearEndpoint,
						sessionClearReturnParameter: settings.sessionClearReturnParameter,
						authorizationParameters: settings.authorizationParameters,
						redirectTarget: logoutUrl,
						returnTo,
						returnToWasProviderRelative: returnTo !== authorizationUrl,
					});
					return this.redirect(logoutUrl);
				}
			}
			await diagnostics.recordAuthorizationStart({
				stage: 'authorization',
				clearProviderSessionBeforeLogin: settings.clearProviderSessionBeforeLogin,
				forceProviderLogin: settings.forceProviderLogin,
				hasEndSessionEndpoint: !!settings.endSessionEndpoint,
				sessionClearEndpointOverride: !!settings.sessionClearEndpoint,
				sessionClearReturnParameter: settings.sessionClearReturnParameter,
				authorizationParameters: settings.authorizationParameters,
				redirectTarget: authorizationUrl,
			});
			return this.redirect(authorizationUrl);
		}

		const stateData = stateStore.consume(req, callbackParams.state);
		const tokenSet = await oidc.exchangeCode(settings, callbackParams.code, stateData, redirectUri);
		if (!tokenSet || !tokenSet.access_token) {
			logger.warn('unexpected provider response', { reason: 'missing access token' });
			return this.error(new Error('OIDC token response did not include an access token'));
		}
		if (!tokenSet.id_token) {
			logger.warn('unexpected provider response', { reason: 'missing id token' });
			return this.error(new Error('OIDC token response did not include an ID token'));
		}

		idClaims = oidc.claimsFromTokenSet(settings, tokenSet, stateData);
		userinfoClaims = await oidc.getUserinfo(settings, tokenSet.access_token, idClaims.sub);
		mergedClaims = oidc.mergeClaims(idClaims, userinfoClaims);
		const claims = oidc.normalizeClaims(mergedClaims);
		const nodebbUser = await identity.resolve(claims, {
			issuer: settings.issuer,
			allowAccountCreation: settings.allowAccountCreation,
			accountLinkingPolicy: settings.accountLinkingPolicy,
			usernameCollisionPolicy: settings.usernameCollisionPolicy,
			nodebbSessionId: req.sessionID || '',
		});
		try {
			await profileSync.syncProfile(nodebbUser.uid, claims, settings);
		} catch (syncErr) {
			logger.warn('profile sync failed after successful oidc identity resolution', {
				uid: nodebbUser.uid,
				message: syncErr.message,
			});
		}
		return this.success(nodebbUser);
	} catch (err) {
		try {
			await diagnostics.recordFailure({
				err,
				stage: req.query.code ? 'callback' : 'authorization',
				settings,
				idClaims,
				userinfoClaims,
				mergedClaims,
			});
		} catch (diagnosticsErr) {
			logger.warn('failed to record sanitized oidc diagnostics', { message: diagnosticsErr.message });
		}
		if (err.level === 'warn') {
			logger.warn(err.message, { code: err.code });
			return this.fail({ message: err.message });
		}
		logger.error(err.stack || err.message);
		return this.error(err);
	}
};

function parseCallbackParams(req, redirectUri) {
	const query = req.query || {};
	const isCallbackRouteRequest = isCallbackRoute(req, redirectUri);
	if (isCallbackRouteRequest && req.method && req.method.toUpperCase() !== 'GET') {
		throw fail('invalid-callback-method', 'OIDC callback must use GET', 'warn');
	}
	const hasCallbackParam = Object.prototype.hasOwnProperty.call(query, 'code') ||
		Object.prototype.hasOwnProperty.call(query, 'state');
	if (!hasCallbackParam) {
		if (isCallbackRouteRequest) {
			throw fail('invalid-callback', 'OIDC callback must include code and state', 'warn');
		}
		return { isCallback: false };
	}
	if (typeof query.code !== 'string' || !query.code.trim()) {
		throw fail('invalid-callback-code', 'OIDC callback code must be a single non-empty value', 'warn');
	}
	if (typeof query.state !== 'string' || !query.state.trim()) {
		throw fail('invalid-callback-state', 'OIDC callback state must be a single non-empty value', 'warn');
	}
	return {
		isCallback: true,
		code: query.code.trim(),
		state: query.state.trim(),
	};
}

function isCallbackRoute(req, redirectUri) {
	if (!req || !redirectUri) {
		return false;
	}
	let callbackPath = '';
	try {
		callbackPath = new URL(redirectUri).pathname;
	} catch (err) {
		return false;
	}
	const candidates = [
		req.path,
		req.originalUrl,
		req.url,
	].filter(value => typeof value === 'string' && value.length > 0);
	return candidates.some((candidate) => {
		try {
			return new URL(candidate, 'https://forum.local').pathname === callbackPath;
		} catch (err) {
			return false;
		}
	});
}

function markProviderSessionClearPending(req) {
	req.session = req.session || {};
	req.session[SESSION_CLEAR_MARKER] = true;
}

function consumeProviderSessionCleared(req) {
	if (!req.session || req.session[SESSION_CLEAR_MARKER] !== true) {
		return false;
	}
	delete req.session[SESSION_CLEAR_MARKER];
	return true;
}

AuthentikOidcStrategy.parseCallbackParams = parseCallbackParams;
AuthentikOidcStrategy.isCallbackRoute = isCallbackRoute;

module.exports = AuthentikOidcStrategy;
