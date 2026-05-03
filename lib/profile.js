'use strict';

const user = require.main.require('./src/user');

const LINK_FIELDS = [
	'authentikSub',
	'authentikIssuer',
	'authentikLinkedAt',
	'authentikLastLoginAt',
	'authentikLastEmail',
];
const DEFAULT_DISPLAY_NAME = 'Authentik';

function timestampToIso(value) {
	const timestamp = parseInt(value, 10);
	if (!Number.isFinite(timestamp) || timestamp <= 0) {
		return '';
	}
	return new Date(timestamp).toISOString();
}

async function getUserFields(uid, fields) {
	if (typeof user.getUserFields === 'function') {
		return await user.getUserFields(uid, fields);
	}
	const values = await Promise.all(fields.map(field => user.getUserField(uid, field)));
	return fields.reduce((memo, field, index) => {
		memo[field] = values[index];
		return memo;
	}, {});
}

function externalLinks(settings) {
	const config = require('./config');
	return [
		{
			id: 'profile',
			label: 'Profile',
			icon: 'fa-user',
			url: settings.selfServiceProfileUrl,
		},
		{
			id: 'password',
			label: 'Password',
			icon: 'fa-key',
			url: settings.selfServicePasswordUrl,
		},
		{
			id: 'mfa',
			label: 'Multi-factor',
			icon: 'fa-shield-halved',
			url: settings.selfServiceMfaUrl,
		},
		{
			id: 'sessions',
			label: 'Sessions',
			icon: 'fa-clock-rotate-left',
			url: settings.selfServiceSessionsUrl,
		},
	].filter((link) => {
		if (!link.url) {
			return false;
		}
		try {
			config.assertSafeUrl(link.url, link.id, {
				required: false,
				allowHttp: !!settings.allowInsecureCallbackUrlForDevelopment,
			});
			return true;
		} catch (err) {
			return false;
		}
	});
}

async function getLinkedAccountState(uid, settings) {
	const fields = await getUserFields(uid, LINK_FIELDS);
	const linked = typeof fields.authentikSub === 'string' && fields.authentikSub.length > 0;
	const links = externalLinks(settings);
	return {
		linked,
		providerName: settings.displayName || DEFAULT_DISPLAY_NAME,
		issuer: fields.authentikIssuer || '',
		linkedAt: timestampToIso(fields.authentikLinkedAt),
		lastLoginAt: timestampToIso(fields.authentikLastLoginAt),
		lastProviderEmail: fields.authentikLastEmail || '',
		externalLinks: links,
		managedFields: [],
		hasExternalLinks: links.length > 0,
	};
}

async function renderLinkedAccountPage(req, res, next) {
	const accountHelpers = require.main.require('./src/controllers/accounts/helpers');
	const controllerHelpers = require.main.require('./src/controllers/helpers');
	const config = require('./config');
	const userData = await accountHelpers.getUserDataByUserSlug(req.params.userslug, req.uid, req.query);
	if (!userData) {
		return next();
	}
	const settings = await config.getSettings();
	userData.authentikOidc = await getLinkedAccountState(userData.uid, settings);
	userData.title = `${userData.authentikOidc.providerName} account`;
	userData.breadcrumbs = controllerHelpers.buildBreadcrumbs([
		{ text: userData.username, url: `/user/${userData.userslug}` },
		{ text: userData.title },
	]);
	res.render('account/authentik-oidc', userData);
}

async function addProfileMenuItem(data) {
	data.links.push({
		id: 'authentik-oidc',
		route: 'authentik-oidc',
		icon: 'fa-right-to-bracket',
		name: 'Authentik OIDC',
		visibility: {
			self: true,
			other: false,
			moderator: false,
			globalMod: false,
			admin: false,
		},
	});
	return data;
}

module.exports = {
	externalLinks,
	getLinkedAccountState,
	addProfileMenuItem,
	renderLinkedAccountPage,
};
