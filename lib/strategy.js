'use strict';

const Strategy = require('passport-strategy');
const util = require('node:util');

const identity = require('./identity');
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
	try {
		const settings = await this.config.getSettings();
		const redirectUri = this.config.getCallbackUrl();

		if (!req.query.code) {
			const stateData = stateStore.create(req, options.state, { usePkce: settings.usePkce });
			return this.redirect(oidc.authorizationUrl(settings, redirectUri, options.state, stateData));
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

		const idClaims = await oidc.verifyIdToken(settings, tokenSet.id_token, stateData.nonce);
		const userinfoClaims = await oidc.getUserinfo(settings, tokenSet.access_token);
		const claims = oidc.normalizeClaims(oidc.mergeClaims(idClaims, userinfoClaims));
		const nodebbUser = await identity.resolve(claims, { issuer: settings.issuer });
		return this.success(nodebbUser);
	} catch (err) {
		if (err.level === 'warn') {
			logger.warn(err.message, { code: err.code });
			return this.fail({ message: err.message });
		}
		logger.error(err.stack || err.message);
		return this.error(err);
	}
};

module.exports = AuthentikOidcStrategy;
