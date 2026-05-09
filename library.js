'use strict';

const passport = module.parent.require('passport');
const routeHelpers = require.main.require('./src/routes/helpers');
const privileges = require.main.require('./src/privileges');

const admin = require('./lib/admin');
const config = require('./lib/config');
const logout = require('./lib/logout');
const profile = require('./lib/profile');
const routing = require('./lib/routing');
const AuthentikOidcStrategy = require('./lib/strategy');

const plugin = module.exports;

plugin.init = async function ({ router, middleware }) {
	await config.ensureDefaults();
	router.get('/register', routing.handleRegisterRoute);
	router.post('/auth/authentik/backchannel-logout', logout.handleBackchannelLogout);
	routeHelpers.setupAdminPageRoute(router, '/admin/plugins/authentik-oidc', admin.renderAdminPage);
	routeHelpers.setupPageRoute(router, '/user/:userslug/authentik-oidc', [
		middleware.exposeUid,
		middleware.ensureLoggedIn,
		middleware.canViewUsers,
		middleware.checkAccountPermissions,
	], profile.renderLinkedAccountPage);
};

plugin.registerApiRoutes = async function ({ router, middleware }) {
	const adminMiddlewares = [middleware.ensureLoggedIn, ensureSettingsAdmin];

	routeHelpers.setupApiRoute(
		router,
		'get',
		'/authentik-oidc/settings',
		adminMiddlewares,
		admin.getSettings
	);
	routeHelpers.setupApiRoute(
		router,
		'post',
		'/authentik-oidc/settings',
		adminMiddlewares,
		admin.saveSettings
	);
	routeHelpers.setupApiRoute(
		router,
		'post',
		'/authentik-oidc/discover',
		adminMiddlewares,
		admin.discover
	);
	routeHelpers.setupApiRoute(
		router,
		'post',
		'/authentik-oidc/jwks/test',
		adminMiddlewares,
		admin.testJwks
	);
	routeHelpers.setupApiRoute(
		router,
		'get',
		'/authentik-oidc/mappings/audit',
		adminMiddlewares,
		admin.auditMappings
	);
	routeHelpers.setupApiRoute(
		router,
		'get',
		'/authentik-oidc/diagnostics/last-failure',
		adminMiddlewares,
		admin.getLastFailure
	);
	routeHelpers.setupApiRoute(
		router,
		'get',
		'/authentik-oidc/diagnostics/last-logout',
		adminMiddlewares,
		admin.getLastLogoutEvent
	);
	routeHelpers.setupApiRoute(
		router,
		'get',
		'/authentik-oidc/diagnostics/last-authorization',
		adminMiddlewares,
		admin.getLastAuthorizationStart
	);
	routeHelpers.setupApiRoute(
		router,
		'post',
		'/authentik-oidc/mappings/repair-stale',
		adminMiddlewares,
		admin.repairStaleMappings
	);
};

async function ensureSettingsAdmin(req, res, next) {
	if (!await privileges.admin.can('admin:settings', req.uid)) {
		return res.status(403).json({ message: 'Not allowed' });
	}
	next();
}

plugin.addAdminNavigation = async function (header) {
	header.authentication.push({
		route: '/plugins/authentik-oidc',
		icon: 'fa-lock',
		name: 'Authentik OIDC',
	});
	return header;
};

plugin.addProfileMenuItem = profile.addProfileMenuItem;

plugin.initAuth = async function (strategies) {
	const settings = await config.getSettings();
	if (!settings.enabled) {
		return strategies;
	}

	passport.use('authentik', new AuthentikOidcStrategy({ config }));
	strategies.push({
		name: 'authentik',
		url: '/auth/authentik',
		callbackURL: '/auth/authentik/callback',
		icon: 'fa-right-to-bracket',
		icons: {
			normal: 'fa fa-right-to-bracket',
			square: 'fa fa-right-to-bracket',
		},
		labels: {
			login: settings.displayName || 'Authentik',
			register: settings.displayName || 'Authentik',
		},
		color: '#fd4b2d',
		scope: settings.scopes || config.DEFAULTS.scopes,
		checkState: true,
	});
	return strategies;
};

plugin.whitelistUserFields = async function (payload) {
	return payload;
};
