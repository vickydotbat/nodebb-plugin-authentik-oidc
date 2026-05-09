'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

function loadStrategy(stubs) {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'passport-strategy') {
			return function Strategy() {};
		}
		if (parent && parent.filename === path.resolve(__dirname, '../lib/strategy.js')) {
			if (request === './identity') {
				return stubs.identity;
			}
			if (request === './diagnostics') {
				return stubs.diagnostics;
			}
			if (request === './errors') {
				return stubs.errors;
			}
			if (request === './logger') {
				return stubs.logger;
			}
			if (request === './oidc') {
				return stubs.oidc;
			}
			if (request === './state') {
				return stubs.state;
			}
			if (request === './sync') {
				return stubs.sync;
			}
		}
		return originalLoad.call(this, request, parent, isMain);
	};

	delete require.cache[require.resolve('../lib/strategy')];
	const AuthentikOidcStrategy = require('../lib/strategy');
	return {
		AuthentikOidcStrategy,
		restore() {
			delete require.cache[require.resolve('../lib/strategy')];
			Module._load = originalLoad;
		},
	};
}

test('callback login succeeds when post-login profile sync fails', async () => {
	const warnings = [];
	let diagnosticsCalled = false;
	const { AuthentikOidcStrategy, restore } = loadStrategy({
		identity: {
			async resolve() {
				return { uid: 42 };
			},
		},
		diagnostics: {
			async recordAuthorizationStart() {},
			async recordFailure() {
				diagnosticsCalled = true;
			},
		},
		errors: {
			fail(code, message, level = 'warn') {
				const err = new Error(message);
				err.code = code;
				err.level = level;
				return err;
			},
		},
		logger: {
			info() {},
			warn(message, meta) {
				warnings.push({ message, meta });
			},
			error(err) {
				throw err instanceof Error ? err : new Error(String(err));
			},
		},
		oidc: {
			async exchangeCode() {
				return {
					access_token: 'access-token',
					id_token: 'id-token',
					claims() {
						return {
							sub: 'sub-1',
							email: 'person@example.com',
							email_verified: true,
						};
					},
				};
			},
			claimsFromTokenSet(settings, tokenSet) {
				return tokenSet.claims();
			},
			async getUserinfo() {
				return {
					preferred_username: 'person',
					name: 'Person Example',
				};
			},
			mergeClaims(idClaims, userinfoClaims) {
				return { ...idClaims, ...userinfoClaims };
			},
			normalizeClaims(claims) {
				return claims;
			},
		},
		state: {
			consume() {
				return { nonce: 'nonce-value' };
			},
		},
		sync: {
			async syncProfile() {
				throw new Error('profile sync broke');
			},
		},
	});

	try {
		const strategy = new AuthentikOidcStrategy({
			config: {
				async getSettings() {
					return {
						issuer: 'https://id.example.com',
						allowAccountCreation: true,
						usernameCollisionPolicy: 'unique',
					};
				},
				getCallbackUrl() {
					return 'https://forum.example.com/auth/authentik/callback';
				},
			},
		});

		let successUser;
		let failed = false;
		let errored = false;
		strategy.success = function (user) {
			successUser = user;
		};
		strategy.fail = function () {
			failed = true;
		};
		strategy.error = function () {
			errored = true;
		};

		await strategy.authenticate({
			query: {
				code: 'auth-code',
				state: 'callback-state',
			},
		}, {});

		assert.deepEqual(successUser, { uid: 42 });
		assert.equal(failed, false);
		assert.equal(errored, false);
		assert.equal(diagnosticsCalled, false);
		assert.equal(warnings.length, 1);
		assert.equal(warnings[0].message, 'profile sync failed after successful oidc identity resolution');
		assert.equal(warnings[0].meta.uid, 42);
	} finally {
		restore();
	}
});

test('callback uses openid-client processed claims instead of custom ID token verifier', async () => {
	let verifyCalled = false;
	let successUser = null;
	const { AuthentikOidcStrategy, restore } = loadStrategy({
		identity: {
			async resolve() {
				return { uid: 42 };
			},
		},
		diagnostics: {
			async recordAuthorizationStart() {},
			async recordFailure() {},
		},
		errors: {
			fail(code, message, level = 'warn') {
				const err = new Error(message);
				err.code = code;
				err.level = level;
				return err;
			},
		},
		logger: { info() {}, warn() {}, error() {} },
		oidc: {
			async exchangeCode() {
				return {
					access_token: 'access-token',
					id_token: 'id-token',
					claims() {
						return {
							sub: 'sub-1',
							email: 'person@example.com',
							email_verified: true,
							nonce: 'nonce-value',
							exp: Math.floor(Date.now() / 1000) + 300,
							iat: Math.floor(Date.now() / 1000),
						};
					},
				};
			},
			verifyIdToken() {
				verifyCalled = true;
				throw new Error('custom verifier should not be called');
			},
			claimsFromTokenSet(settings, tokenSet) {
				return tokenSet.claims();
			},
			async getUserinfo() {
				return null;
			},
			mergeClaims(idClaims, userinfoClaims) {
				return { ...idClaims, ...(userinfoClaims || {}) };
			},
			normalizeClaims(claims) {
				return claims;
			},
		},
		state: {
			consume() {
				return { state: 'state-1', nonce: 'nonce-value' };
			},
		},
		sync: { async syncProfile() {} },
	});

	try {
		const strategy = new AuthentikOidcStrategy({
			config: {
				async getSettings() {
					return {
						issuer: 'https://id.example.com',
						allowAccountCreation: true,
						usernameCollisionPolicy: 'unique',
					};
				},
				getCallbackUrl() {
					return 'https://forum.example.com/auth/authentik/callback';
				},
			},
		});
		strategy.success = function (user) {
			successUser = user;
		};
		strategy.error = function (err) {
			throw err;
		};

		await strategy.authenticate({
			method: 'GET',
			path: '/auth/authentik/callback',
			query: {
				code: 'auth-code',
				state: 'state-1',
			},
		}, {});

		assert.equal(verifyCalled, false);
		assert.deepEqual(successUser, { uid: 42 });
	} finally {
		restore();
	}
});

test('callback rejects duplicate code before consuming state', async () => {
	let consumed = false;
	let exchanged = false;
	const { AuthentikOidcStrategy, restore } = loadStrategy({
		identity: { async resolve() { return { uid: 1 }; } },
		diagnostics: { async recordAuthorizationStart() {}, async recordFailure() {} },
		errors: {
			fail(code, message, level = 'warn') {
				const err = new Error(message);
				err.code = code;
				err.level = level;
				return err;
			},
		},
		logger: { info() {}, warn() {}, error() {} },
		oidc: {
			async exchangeCode() { exchanged = true; return {}; },
		},
		state: {
			consume() { consumed = true; return {}; },
		},
		sync: { async syncProfile() {} },
	});
	try {
		const strategy = new AuthentikOidcStrategy({
			config: {
				async getSettings() { return {}; },
				getCallbackUrl() { return 'https://forum.example.com/auth/authentik/callback'; },
			},
		});
		let failed = false;
		strategy.fail = function () { failed = true; };
		strategy.error = function (err) { throw err; };

		await strategy.authenticate({
			query: { code: ['a', 'b'], state: 'state-1' },
		}, {});

		assert.equal(failed, true);
		assert.equal(consumed, false);
		assert.equal(exchanged, false);
	} finally {
		restore();
	}
});

test('callback route without code or state fails closed instead of starting login', async () => {
	let created = false;
	let redirected = false;
	let exchanged = false;
	const { AuthentikOidcStrategy, restore } = loadStrategy({
		identity: { async resolve() { return { uid: 1 }; } },
		diagnostics: { async recordAuthorizationStart() {}, async recordFailure() {} },
		errors: {
			fail(code, message, level = 'warn') {
				const err = new Error(message);
				err.code = code;
				err.level = level;
				return err;
			},
		},
		logger: { info() {}, warn() {}, error() {} },
		oidc: {
			authorizationUrl() { redirected = true; return 'https://auth.example.com/authorize'; },
			async exchangeCode() { exchanged = true; return {}; },
		},
		state: {
			create() { created = true; return { state: 'state-1', nonce: 'nonce-1' }; },
			consume() { throw new Error('should not consume'); },
		},
		sync: { async syncProfile() {} },
	});
	try {
		const strategy = new AuthentikOidcStrategy({
			config: {
				async getSettings() { return {}; },
				getCallbackUrl() { return 'https://forum.example.com/auth/authentik/callback'; },
			},
		});
		let failed = false;
		strategy.redirect = function () { redirected = true; };
		strategy.fail = function () { failed = true; };
		strategy.error = function (err) { throw err; };

		await strategy.authenticate({
			method: 'GET',
			path: '/auth/authentik/callback',
			query: {},
			session: {},
		}, {});

		assert.equal(failed, true);
		assert.equal(created, false);
		assert.equal(redirected, false);
		assert.equal(exchanged, false);
	} finally {
		restore();
	}
});

test('callback route rejects non-GET methods before consuming state', async () => {
	let consumed = false;
	let exchanged = false;
	const { AuthentikOidcStrategy, restore } = loadStrategy({
		identity: { async resolve() { return { uid: 1 }; } },
		diagnostics: { async recordAuthorizationStart() {}, async recordFailure() {} },
		errors: {
			fail(code, message, level = 'warn') {
				const err = new Error(message);
				err.code = code;
				err.level = level;
				return err;
			},
		},
		logger: { info() {}, warn() {}, error() {} },
		oidc: {
			async exchangeCode() { exchanged = true; return {}; },
		},
		state: {
			consume() { consumed = true; return {}; },
		},
		sync: { async syncProfile() {} },
	});
	try {
		const strategy = new AuthentikOidcStrategy({
			config: {
				async getSettings() { return {}; },
				getCallbackUrl() { return 'https://forum.example.com/auth/authentik/callback'; },
			},
		});
		let failed = false;
		strategy.fail = function () { failed = true; };
		strategy.error = function (err) { throw err; };

		await strategy.authenticate({
			method: 'POST',
			path: '/auth/authentik/callback',
			query: { code: 'code-1', state: 'state-1' },
			session: {},
		}, {});

		assert.equal(failed, true);
		assert.equal(consumed, false);
		assert.equal(exchanged, false);
	} finally {
		restore();
	}
});

test('forced attacker-state callback fails in victim session before token exchange', async () => {
	let exchanged = false;
	const { AuthentikOidcStrategy, restore } = loadStrategy({
		identity: { async resolve() { return { uid: 1 }; } },
		diagnostics: { async recordAuthorizationStart() {}, async recordFailure() {} },
		errors: {
			fail(code, message, level = 'warn') {
				const err = new Error(message);
				err.code = code;
				err.level = level;
				return err;
			},
		},
		logger: { info() {}, warn() {}, error() {} },
		oidc: {
			async exchangeCode() { exchanged = true; return {}; },
		},
		state: {
			consume(req, state) {
				if (!req.session.authentikOidc || !req.session.authentikOidc[state]) {
					throw new Error('Missing OIDC state');
				}
				return req.session.authentikOidc[state];
			},
		},
		sync: { async syncProfile() {} },
	});
	try {
		const strategy = new AuthentikOidcStrategy({
			config: {
				async getSettings() { return {}; },
				getCallbackUrl() { return 'https://forum.example.com/auth/authentik/callback'; },
			},
		});
		let success = false;
		let errored = false;
		strategy.success = function () { success = true; };
		strategy.error = function () { errored = true; };

		await strategy.authenticate({
			method: 'GET',
			path: '/auth/authentik/callback',
			query: { code: 'attacker-code', state: 'attacker-state' },
			session: {},
		}, {});

		assert.equal(errored, true);
		assert.equal(success, false);
		assert.equal(exchanged, false);
	} finally {
		restore();
	}
});

test('query flag cannot bypass provider session clearing without server marker', async () => {
	let created = false;
	const redirects = [];
	const { AuthentikOidcStrategy, restore } = loadStrategy({
		identity: { async resolve() { return { uid: 1 }; } },
		diagnostics: { async recordAuthorizationStart() {} },
		errors: {
			fail(code, message, level = 'warn') {
				const err = new Error(message);
				err.code = code;
				err.level = level;
				return err;
			},
		},
		logger: { info() {}, warn() {}, error() {} },
		oidc: {
			authorizationUrl() { return 'https://auth.example.com/application/o/nodebb/authorize/?client_id=nodebb'; },
			providerRelativeUrl(target) { return new URL(target).pathname; },
			providerLogoutUrl(settings, returnTo) {
				return `${settings.sessionClearEndpoint}?next=${encodeURIComponent(returnTo)}`;
			},
		},
		state: {
			create() {
				created = true;
				return { state: 'state-1', nonce: 'nonce-1', codeChallenge: 'challenge-1' };
			},
		},
		sync: { async syncProfile() {} },
	});
	try {
		const strategy = new AuthentikOidcStrategy({
			config: {
				async getSettings() {
					return {
						clearProviderSessionBeforeLogin: true,
						forceProviderLogin: true,
						sessionClearEndpoint: 'https://auth.example.com/if/flow/default-invalidation-flow/',
						sessionClearReturnParameter: 'next',
					};
				},
				getCallbackUrl() { return 'https://forum.example.com/auth/authentik/callback'; },
				getLoginUrl() { return 'https://forum.example.com/auth/authentik'; },
			},
		});
		strategy.redirect = function (url) { redirects.push(url); };
		await strategy.authenticate({
			query: { authentikFreshLogin: '1' },
			session: {},
		}, {});

		assert.equal(created, true);
		assert.equal(redirects.length, 1);
		assert.equal(redirects[0].startsWith('https://auth.example.com/if/flow/default-invalidation-flow/'), true);
	} finally {
		restore();
	}
});

test('provider session clearing ignores request redirect parameters', async () => {
	const redirects = [];
	const { AuthentikOidcStrategy, restore } = loadStrategy({
		identity: { async resolve() { return { uid: 1 }; } },
		diagnostics: { async recordAuthorizationStart() {} },
		errors: {
			fail(code, message, level = 'warn') {
				const err = new Error(message);
				err.code = code;
				err.level = level;
				return err;
			},
		},
		logger: { info() {}, warn() {}, error() {} },
		oidc: {
			authorizationUrl() { return 'https://auth.example.com/application/o/nodebb/authorize/?client_id=nodebb'; },
			providerRelativeUrl(target) { return new URL(target).pathname; },
			providerLogoutUrl(settings, returnTo) {
				return `${settings.sessionClearEndpoint}?next=${encodeURIComponent(returnTo)}`;
			},
		},
		state: {
			create() {
				return { state: 'state-1', nonce: 'nonce-1', codeChallenge: 'challenge-1' };
			},
		},
		sync: { async syncProfile() {} },
	});
	try {
		const strategy = new AuthentikOidcStrategy({
			config: {
				async getSettings() {
					return {
						clearProviderSessionBeforeLogin: true,
						sessionClearEndpoint: 'https://auth.example.com/if/flow/default-invalidation-flow/',
						sessionClearReturnParameter: 'next',
					};
				},
				getCallbackUrl() { return 'https://forum.example.com/auth/authentik/callback'; },
				getLoginUrl() { return 'https://forum.example.com/auth/authentik'; },
			},
		});
		strategy.redirect = function (url) { redirects.push(url); };
		await strategy.authenticate({
			method: 'GET',
			query: {
				next: 'https://evil.com/',
				returnTo: 'https://evil.com/',
				callback: 'https://evil.com/',
				redirect: 'https://evil.com/',
				post_logout_redirect_uri: 'https://evil.com/',
			},
			session: {},
		}, {});

		assert.equal(redirects.length, 1);
		assert.equal(decodeURIComponent(redirects[0]).includes('evil.com'), false);
	} finally {
		restore();
	}
});

test('authorization redirect uses configured callback URL despite hostile host headers', async () => {
	let redirectUrl = '';
	const { AuthentikOidcStrategy, restore } = loadStrategy({
		identity: { async resolve() { return { uid: 1 }; } },
		diagnostics: { async recordAuthorizationStart() {} },
		errors: {
			fail(code, message, level = 'warn') {
				const err = new Error(message);
				err.code = code;
				err.level = level;
				return err;
			},
		},
		logger: { info() {}, warn() {}, error() {} },
		oidc: {
			authorizationUrl(settings, redirectUri) {
				return `https://auth.example.com/authorize?redirect_uri=${encodeURIComponent(redirectUri)}`;
			},
		},
		state: {
			create() {
				return { state: 'state-1', nonce: 'nonce-1', codeChallenge: 'challenge-1' };
			},
		},
		sync: { async syncProfile() {} },
	});
	try {
		const strategy = new AuthentikOidcStrategy({
			config: {
				async getSettings() { return {}; },
				getCallbackUrl() { return 'https://forum.example.com/auth/authentik/callback'; },
			},
		});
		strategy.redirect = function (url) { redirectUrl = url; };
		await strategy.authenticate({
			method: 'GET',
			headers: {
				host: 'evil.com',
				'x-forwarded-host': 'evil.com',
			},
			query: {},
			session: {},
		}, {});

		assert.equal(new URL(redirectUrl).searchParams.get('redirect_uri'), 'https://forum.example.com/auth/authentik/callback');
		assert.equal(redirectUrl.includes('evil.com'), false);
	} finally {
		restore();
	}
});

test('token endpoint failure logs sanitized error and does not create a session', async () => {
	let success = false;
	let diagnosticsMessage = '';
	let logMessage = '';
	const { AuthentikOidcStrategy, restore } = loadStrategy({
		identity: { async resolve() { return { uid: 1 }; } },
		diagnostics: {
			async recordAuthorizationStart() {},
			async recordFailure({ err }) {
				diagnosticsMessage = err.message;
			},
		},
		errors: {
			fail(code, message, level = 'warn') {
				const err = new Error(message);
				err.code = code;
				err.level = level;
				return err;
			},
		},
		logger: {
			info() {},
			warn() {},
			error(message) { logMessage = require('../lib/redact').redactString(message); },
		},
		oidc: {
			async exchangeCode() {
				throw new Error('HTTP 400 code=secret-code client_secret=secret-secret access_token=secret-access');
			},
		},
		state: {
			consume() { return { state: 'state-1', nonce: 'nonce-1', codeVerifier: 'verifier-1' }; },
		},
		sync: { async syncProfile() {} },
	});
	try {
		const strategy = new AuthentikOidcStrategy({
			config: {
				async getSettings() { return {}; },
				getCallbackUrl() { return 'https://forum.example.com/auth/authentik/callback'; },
			},
		});
		strategy.success = function () { success = true; };
		strategy.error = function () {};

		await strategy.authenticate({
			method: 'GET',
			path: '/auth/authentik/callback',
			query: { code: 'auth-code', state: 'state-1' },
			session: {},
		}, {});

		assert.equal(success, false);
		assert.equal(diagnosticsMessage.includes('secret-code'), true);
		assert.equal(logMessage.includes('secret-code'), false);
		assert.equal(logMessage.includes('secret-secret'), false);
		assert.equal(logMessage.includes('secret-access'), false);
	} finally {
		restore();
	}
});
