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
				};
			},
			async verifyIdToken() {
				return {
					sub: 'sub-1',
					email: 'person@example.com',
					email_verified: true,
				};
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
