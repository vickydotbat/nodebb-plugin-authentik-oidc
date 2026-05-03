'use strict';

const config = require('./config');
const diagnostics = require('./diagnostics');
const discovery = require('./discovery');
const logger = require('./logger');
const mappings = require('./mappings');

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
	const metadata = await discovery.discover(issuer);
	logger.info('discovery succeeded', { issuer: metadata.issuer });
	res.json(metadata);
}

async function auditMappings(req, res) {
	res.json(await mappings.audit());
}

async function getLastFailure(req, res) {
	res.json(await diagnostics.getLastFailure() || {});
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
	auditMappings,
	getLastFailure,
	repairStaleMappings,
};
