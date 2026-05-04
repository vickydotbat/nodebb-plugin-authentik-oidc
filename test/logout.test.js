'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const { createMocks, installNodebbMocks } = require('./bootstrap');

function loadLogout(mocks, logoutTokenClaims) {
	const restoreNodebb = installNodebbMocks(mocks);
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === './oidc' && parent && parent.filename.endsWith('/lib/logout.js')) {
			return {
				async verifyLogoutToken() {
					return logoutTokenClaims;
				},
			};
		}
		return originalLoad.call(this, request, parent, isMain);
	};
	[
		'../lib/config',
		'../lib/identity',
		'../lib/logout',
	].forEach((modulePath) => {
		delete require.cache[require.resolve(modulePath)];
	});
	const logout = require('../lib/logout');
	return {
		logout,
		restore() {
			Module._load = originalLoad;
			restoreNodebb();
			delete require.cache[require.resolve('../lib/logout')];
		},
	};
}

function response() {
	return {
		statusCode: 0,
		body: null,
		sendStatus(code) {
			this.statusCode = code;
			return this;
		},
		status(code) {
			this.statusCode = code;
			return this;
		},
		json(body) {
			this.body = body;
			return this;
		},
	};
}

test('back-channel logout revokes NodeBB sessions when enabled and sub maps to uid', async () => {
	const mocks = createMocks();
	mocks.state.subToUid.set('sub-1', 42);
	mocks.state.users.set(42, { uid: 42, username: 'linked' });
	mocks.state.settings.set('authentik-oidc', {
		backchannelLogoutEnabled: true,
		clientId: 'nodebb',
		issuer: 'https://auth.example.com/application/o/nodebb/',
		jwksUri: 'https://auth.example.com/jwks/',
	});
	const { logout, restore } = loadLogout(mocks, { sub: 'sub-1', sid: 'sid-1' });
	try {
		const res = response();
		await logout.handleBackchannelLogout({
			body: { logout_token: 'signed-token' },
			query: {},
		}, res);
		assert.equal(res.statusCode, 204);
		assert.deepEqual(mocks.state.revokedSessionsForUids, [42]);
	} finally {
		restore();
	}
});

test('back-channel logout can map sid to uid and removes used sid mapping', async () => {
	const mocks = createMocks();
	mocks.state.sidToUid.set('sid-1', 42);
	mocks.state.users.set(42, { uid: 42, username: 'linked' });
	mocks.state.settings.set('authentik-oidc', {
		backchannelLogoutEnabled: true,
		clientId: 'nodebb',
		issuer: 'https://auth.example.com/application/o/nodebb/',
		jwksUri: 'https://auth.example.com/jwks/',
	});
	const { logout, restore } = loadLogout(mocks, { sid: 'sid-1' });
	try {
		const res = response();
		await logout.handleBackchannelLogout({
			body: { logout_token: 'signed-token' },
			query: {},
		}, res);
		assert.equal(res.statusCode, 204);
		assert.deepEqual(mocks.state.revokedSessionsForUids, [42]);
		assert.equal(mocks.state.sidToUid.has('sid-1'), false);
	} finally {
		restore();
	}
});

test('back-channel logout does not revoke sessions while disabled', async () => {
	const mocks = createMocks();
	mocks.state.subToUid.set('sub-1', 42);
	mocks.state.settings.set('authentik-oidc', {
		backchannelLogoutEnabled: false,
	});
	const { logout, restore } = loadLogout(mocks, { sub: 'sub-1' });
	try {
		const res = response();
		await logout.handleBackchannelLogout({
			body: { logout_token: 'signed-token' },
			query: {},
		}, res);
		assert.equal(res.statusCode, 204);
		assert.deepEqual(mocks.state.revokedSessionsForUids, []);
	} finally {
		restore();
	}
});
