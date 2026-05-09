'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const { createMocks, installNodebbMocks } = require('./bootstrap');

function loadLibrary(mocks, helpers) {
	const restoreNodebb = installNodebbMocks(mocks);
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'passport-strategy') {
			return function Strategy() {};
		}
		if (request === 'passport') {
			return { use() {} };
		}
		if (request === './src/routes/helpers') {
			return helpers || {
				setupAdminPageRoute() {},
				setupPageRoute() {},
				setupApiRoute() {},
			};
		}
		if (request === './src/privileges') {
			return { admin: { can: async () => true } };
		}
		return originalLoad.call(this, request, parent, isMain);
	};
	[
		'../lib/config',
		'../lib/strategy',
		'../library',
	].forEach((modulePath) => {
		delete require.cache[require.resolve(modulePath)];
	});
	const library = require('../library');
	return {
		library,
		restore() {
			[
				'../lib/config',
				'../lib/strategy',
				'../library',
			].forEach((modulePath) => {
				delete require.cache[require.resolve(modulePath)];
			});
			Module._load = originalLoad;
			restoreNodebb();
		},
	};
}

test('user whitelist excludes raw OIDC identity and email fields', async () => {
	const mocks = createMocks();
	const { library, restore } = loadLibrary(mocks);
	try {
		const payload = { whitelist: [] };
		await library.whitelistUserFields(payload);
		assert.equal(payload.whitelist.includes('authentikSub'), false);
		assert.equal(payload.whitelist.includes('authentikIssuer'), false);
		assert.equal(payload.whitelist.includes('authentikLastEmail'), false);
		assert.equal(payload.whitelist.includes('authentikLinkedAt'), false);
		assert.equal(payload.whitelist.includes('authentikLastLoginAt'), false);
		assert.equal(payload.whitelist.includes('authentikLastSyncedAt'), false);
	} finally {
		restore();
	}
});

test('admin mutation API routes include explicit CSRF middleware when NodeBB exposes one', async () => {
	const mocks = createMocks();
	const csrf = function csrf() {};
	const routeCalls = [];
	const helpers = {
		setupAdminPageRoute() {},
		setupPageRoute() {},
		setupApiRoute(router, method, route, middlewares, handler) {
			routeCalls.push({ method, route, middlewares, handler });
		},
	};
	mocks.routeHelpers = helpers;
	const { library, restore } = loadLibrary(mocks, helpers);
	try {
		await library.registerApiRoutes({
			router: {},
			middleware: {
				ensureLoggedIn() {},
				applyCSRF: csrf,
			},
		});
		const mutationRoutes = routeCalls.filter(call => call.method === 'post');
		assert.deepEqual(
			mutationRoutes.map(call => call.route).sort(),
			[
				'/authentik-oidc/discover',
				'/authentik-oidc/jwks/test',
				'/authentik-oidc/mappings/repair-stale',
				'/authentik-oidc/settings',
			]
		);
		mutationRoutes.forEach((call) => {
			assert.equal(call.middlewares.includes(csrf), true, `${call.route} missing csrf middleware`);
		});
	} finally {
		restore();
	}
});

test('app init registers login/register intercepts and back-channel logout route', async () => {
	const mocks = createMocks();
	const getRoutes = [];
	const postRoutes = [];
	const { library, restore } = loadLibrary(mocks);
	try {
		await library.init({
			router: {
				get(path, handler) {
					getRoutes.push({ path, handler });
				},
				post(path, handler) {
					postRoutes.push({ path, handler });
				},
			},
			middleware: {
				exposeUid() {},
				ensureLoggedIn() {},
				canViewUsers() {},
				checkAccountPermissions() {},
			},
		});

		assert.deepEqual(getRoutes.map(route => route.path), ['/login', '/register']);
		assert.deepEqual(postRoutes.map(route => route.path), ['/auth/authentik/backchannel-logout']);
		assert.equal(typeof getRoutes[0].handler, 'function');
		assert.equal(typeof getRoutes[1].handler, 'function');
		assert.equal(typeof postRoutes[0].handler, 'function');
	} finally {
		restore();
	}
});

test('auth strategy disables NodeBB outer state check because plugin validates OIDC state', async () => {
	const mocks = createMocks();
	mocks.state.settings.set('authentik-oidc', {
		enabled: true,
		displayName: 'Authentik',
		scopes: 'openid email profile',
	});
	const { library, restore } = loadLibrary(mocks);
	try {
		const strategies = await library.initAuth([]);
		assert.equal(strategies.length, 1);
		assert.equal(strategies[0].name, 'authentik');
		assert.equal(strategies[0].checkState, false);
	} finally {
		restore();
	}
});

test('admin API route middleware rejects users without admin settings privilege', async () => {
	const mocks = createMocks();
	const routeCalls = [];
	mocks.routeHelpers = {
		setupAdminPageRoute() {},
		setupPageRoute() {},
		setupApiRoute(router, method, route, middlewares, handler) {
			routeCalls.push({ method, route, middlewares, handler });
		},
	};
	mocks.privileges = {
		admin: {
			async can() {
				return false;
			},
		},
	};
	const { library, restore } = loadLibrary(mocks);
	try {
		await library.registerApiRoutes({
			router: {},
			middleware: {
				ensureLoggedIn(req, res, next) { next(); },
				applyCSRF(req, res, next) { next(); },
			},
		});
		const settingsRoute = routeCalls.find(call => call.route === '/authentik-oidc/settings' && call.method === 'post');
		const ensureSettingsAdmin = settingsRoute.middlewares[2];
		let statusCode = 0;
		let body = null;
		await ensureSettingsAdmin(
			{ uid: 42 },
			{
				status(code) {
					statusCode = code;
					return this;
				},
				json(payload) {
					body = payload;
				},
			},
			() => {
				throw new Error('should not continue');
			}
		);
		assert.equal(statusCode, 403);
		assert.deepEqual(body, { message: 'Not allowed' });
	} finally {
		restore();
	}
});
