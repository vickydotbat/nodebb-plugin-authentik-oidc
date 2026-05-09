'use strict';

const meta = require.main.require('./src/meta');

const config = require('./config');
const logger = require('./logger');

function getRequestedNext(req) {
	if (req && req.query && typeof req.query.next === 'string' && req.query.next.trim()) {
		return safeRelativeNext(req.query.next.trim());
	}
	if (req && req.headers && typeof req.headers['x-return-to'] === 'string' && req.headers['x-return-to'].trim()) {
		return safeRelativeNext(req.headers['x-return-to'].trim());
	}
	return '';
}

function safeRelativeNext(value) {
	if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')) {
		return '';
	}
	if (/[\u0000-\u001f\u007f\\]/.test(value)) {
		return '';
	}
	try {
		const parsed = new URL(value, 'https://forum.local');
		if (parsed.origin !== 'https://forum.local') {
			return '';
		}
		return `${parsed.pathname}${parsed.search}${parsed.hash}`;
	} catch (err) {
		return '';
	}
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

function shouldRedirectLogin(req, settings) {
	if (!settings || !settings.enabled) {
		return false;
	}
	if (settings.redirectLoginToProvider !== true) {
		return false;
	}
	if (req.loggedIn || parseInt(req.uid, 10) > 0) {
		return false;
	}
	if (parseInt(req.query && req.query.local, 10) === 1) {
		return false;
	}
	return true;
}

function buildAuthRedirectUrl(req, loginUrl) {
	const url = new URL(loginUrl);
	const next = getRequestedNext(req);
	if (next) {
		url.searchParams.set('next', next);
	}
	return url.toString();
}

function isAuthentikStart(req) {
	const candidates = [
		req && req.path,
		req && req.originalUrl,
		req && req.url,
	].filter(value => typeof value === 'string' && value.length > 0);
	return candidates.some((candidate) => {
		try {
			return new URL(candidate, 'https://forum.local').pathname === '/auth/authentik';
		} catch (err) {
			return false;
		}
	});
}

function filterAuthOptions(payload) {
	const req = payload && payload.req;
	if (!req || !isAuthentikStart(req)) {
		return payload;
	}
	req.session = req.session || {};
	const explicitNext = getRequestedNext(req);
	if (explicitNext) {
		req.session.returnTo = explicitNext;
		req.session.next = explicitNext;
		return payload;
	}
	delete req.session.returnTo;
	delete req.session.next;
	return payload;
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

async function handleLoginRoute(req, res, next) {
	const settings = await config.getSettings();
	if (!shouldRedirectLogin(req, settings)) {
		return next();
	}

	const target = buildAuthRedirectUrl(req, config.getLoginUrl());
	logger.info('redirecting anonymous login route to oidc login', {
		hasNext: !!getRequestedNext(req),
	});
	return res.redirect(target);
}

module.exports = {
	getRequestedNext,
	safeRelativeNext,
	shouldRedirectLogin,
	shouldRedirectRegister,
	buildAuthRedirectUrl,
	filterAuthOptions,
	handleLoginRoute,
	handleRegisterRoute,
};
