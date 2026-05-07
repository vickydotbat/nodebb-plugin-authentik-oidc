'use strict';

const meta = require.main.require('./src/meta');

const config = require('./config');
const logger = require('./logger');

function getRequestedNext(req) {
	if (req && req.query && typeof req.query.next === 'string' && req.query.next.trim()) {
		return req.query.next.trim();
	}
	if (req && req.headers && typeof req.headers['x-return-to'] === 'string' && req.headers['x-return-to'].trim()) {
		return req.headers['x-return-to'].trim();
	}
	return '';
}

function shouldRedirectRegister(req, settings) {
	if (!settings || !settings.enabled) {
		return false;
	}
	if (settings.redirectRegisterToLogin === false) {
		return false;
	}
	if (req.loggedIn || parseInt(req.uid, 10) > 0) {
		return false;
	}
	if (parseInt(req.query && req.query.local, 10) === 1) {
		return false;
	}
	if (req.query && req.query.token) {
		return false;
	}
	const registrationType = meta.config.registrationType || 'normal';
	return !['disabled', 'invite-only', 'admin-invite-only'].includes(registrationType);
}

function buildAuthRedirectUrl(req, loginUrl) {
	const url = new URL(loginUrl);
	const next = getRequestedNext(req);
	if (next) {
		url.searchParams.set('next', next);
	}
	return url.toString();
}

async function handleRegisterRoute(req, res, next) {
	const settings = await config.getSettings();
	if (!shouldRedirectRegister(req, settings)) {
		return next();
	}

	const target = buildAuthRedirectUrl(req, config.getLoginUrl());
	logger.info('redirecting anonymous register route to oidc login', {
		hasNext: !!getRequestedNext(req),
	});
	return res.redirect(target);
}

module.exports = {
	getRequestedNext,
	shouldRedirectRegister,
	buildAuthRedirectUrl,
	handleRegisterRoute,
};
