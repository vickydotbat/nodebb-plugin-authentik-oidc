'use strict';

const Strategy = require('passport-strategy');
const util = require('node:util');

const identity = require('./identity');
const diagnostics = require('./diagnostics');
const { fail } = require('./errors');
const logger = require('./logger');
const oidc = require('./oidc');
const stateStore = require('./state');

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
			return this.redirect(oidc.authorizationUrl(settings, redirectUri, stateData.state, stateData));
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
