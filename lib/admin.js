'use strict';

const config = require('./config');
const diagnostics = require('./diagnostics');
const discovery = require('./discovery');
const logger = require('./logger');
const mappings = require('./mappings');
const oidc = require('./oidc');

async function renderAdminPage(req, res) {
	const settings = config.publicSettings(await config.getSettings());
	res.render('admin/plugins/authentik-oidc', {
		title: 'Authentik OIDC',
		settings,
	});
}

async function getSettings(req, res) {
	res.json(config.publicSettings(await config.getSettings()));
}

async function saveSettings(req, res) {
	try {
		const settings = await config.saveSettings(req.body || {});
		logger.info('settings updated');
		res.json(settings);
	} catch (err) {
		if (err.errors) {
			return res.status(400).json({ message: err.message, errors: err.errors });
		}
		throw err;
	}
}

async function discover(req, res) {
	const issuer = req.body && req.body.issuer;
	if (!issuer) {
		return res.status(400).json({ message: 'Issuer is required' });
	}
	const settings = await config.getSettings();
	try {
		config.assertSafeUrl(issuer, 'issuer', {
			allowHttp: settings.allowInsecureCallbackUrlForDevelopment,
		});
		const metadata = await discovery.discover(issuer);
		logger.info('discovery succeeded', { issuer: metadata.issuer });
		res.json(metadata);
	} catch (err) {
		if (err.statusCode || err.errors) {
			return res.status(err.statusCode || 400).json({ message: err.message, errors: err.errors || {} });
		}
		throw err;
	}
}

async function testJwks(req, res) {
	const jwksUri = req.body && req.body.jwksUri;
	if (!jwksUri) {
		return res.status(400).json({ message: 'JWKS URI is required' });
	}
	const settings = await config.getSettings();
	try {
		config.assertSafeUrl(jwksUri, 'jwksUri', {
			allowHttp: settings.allowInsecureCallbackUrlForDevelopment,
		});
		const result = await oidc.testJwks(jwksUri);
		logger.info('jwks test succeeded', {
			jwksUri,
			supportedSigningKeyCount: result.supportedSigningKeyCount,
		});
		res.json(result);
	} catch (err) {
		logger.warn('jwks test failed', { jwksUri, code: err.code, message: err.message });
		if (err.statusCode || err.errors) {
			return res.status(err.statusCode || 400).json({ message: err.message, errors: err.errors || {} });
		}
		if (err.code) {
			return res.status(400).json({ message: err.message, code: err.code });
		}
		throw err;
	}
}

async function auditMappings(req, res) {
	res.json(await mappings.audit());
}

async function getLastFailure(req, res) {
	res.json(await diagnostics.getLastFailure() || {});
}

async function getLastLogoutEvent(req, res) {
	res.json(await diagnostics.getLastLogoutEvent() || {});
}

async function repairStaleMappings(req, res) {
	try {
		res.json(await mappings.repairStaleMappings({
			confirm: !!(req.body && req.body.confirm),
		}));
	} catch (err) {
		if (err.statusCode) {
			return res.status(err.statusCode).json({ message: err.message });
		}
		throw err;
	}
}

module.exports = {
	renderAdminPage,
	getSettings,
	saveSettings,
	discover,
	testJwks,
	auditMappings,
	getLastFailure,
	getLastLogoutEvent,
	repairStaleMappings,
};
