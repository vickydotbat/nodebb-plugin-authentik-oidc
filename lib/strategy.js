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

		if (!req.query.code) {
			const stateData = stateStore.create(req, options.state, { usePkce: settings.usePkce });
			const authorizationUrl = oidc.authorizationUrl(settings, redirectUri, stateData.state, stateData);
			if (settings.clearProviderSessionBeforeLogin && !req.query.authentikFreshLogin) {
				const returnTo = settings.sessionClearReturnParameter === 'next' ?
					oidc.providerRelativeUrl(authorizationUrl, settings.sessionClearEndpoint || settings.endSessionEndpoint) :
					`${this.config.getLoginUrl()}?authentikFreshLogin=1`;
				const logoutUrl = oidc.providerLogoutUrl(settings, returnTo);
				if (logoutUrl) {
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

		const stateData = stateStore.consume(req, req.query.state);
		const tokenSet = await oidc.exchangeCode(settings, req.query.code, stateData, redirectUri);
		if (!tokenSet || !tokenSet.access_token) {
			logger.warn('unexpected provider response', { reason: 'missing access token' });
			return this.error(new Error('OIDC token response did not include an access token'));
		}
		if (!tokenSet.id_token) {
			logger.warn('unexpected provider response', { reason: 'missing id token' });
			return this.error(new Error('OIDC token response did not include an ID token'));
		}

		idClaims = await oidc.verifyIdToken(settings, tokenSet.id_token, stateData.nonce);
		userinfoClaims = await oidc.getUserinfo(settings, tokenSet.access_token);
		mergedClaims = oidc.mergeClaims(idClaims, userinfoClaims);
		const claims = oidc.normalizeClaims(mergedClaims);
		const nodebbUser = await identity.resolve(claims, {
			issuer: settings.issuer,
			allowAccountCreation: settings.allowAccountCreation,
			usernameCollisionPolicy: settings.usernameCollisionPolicy,
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

module.exports = AuthentikOidcStrategy;
