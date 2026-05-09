'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const { Readable } = require('node:stream');

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
		'../lib/diagnostics',
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
		const diagnostics = require('../lib/diagnostics');
		const event = await diagnostics.getLastLogoutEvent();
		assert.equal(event.outcome, 'revoked');
		assert.equal(event.tokenValidated, true);
		assert.equal(event.uid, 42);
	} finally {
		restore();
	}
});

test('back-channel logout accepts form-encoded logout token bodies', async () => {
	const mocks = createMocks();
	mocks.state.subToUid.set('sub-1', 42);
	mocks.state.users.set(42, { uid: 42, username: 'linked' });
	mocks.state.settings.set('authentik-oidc', {
		backchannelLogoutEnabled: true,
		clientId: 'nodebb',
		issuer: 'https://auth.example.com/application/o/nodebb/',
		jwksUri: 'https://auth.example.com/jwks/',
	});
	const { logout, restore } = loadLogout(mocks, { sub: 'sub-1' });
	try {
		const req = Readable.from(['logout_token=signed-token']);
		req.body = {};
		req.query = {};
		req.headers = { 'content-type': 'application/x-www-form-urlencoded' };
		const res = response();
		await logout.handleBackchannelLogout(req, res);
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

test('back-channel logout with sid revokes only mapped NodeBB session when available', async () => {
	const mocks = createMocks();
	mocks.state.sidToUid.set('sid-1', {
		uid: 42,
		issuer: 'https://auth.example.com/application/o/nodebb/',
		sub: 'sub-1',
		sessionId: 'nodebb-session-1',
	});
	mocks.state.users.set(42, { uid: 42, username: 'linked' });
	mocks.state.settings.set('authentik-oidc', {
		backchannelLogoutEnabled: true,
		clientId: 'nodebb',
		issuer: 'https://auth.example.com/application/o/nodebb/',
		jwksUri: 'https://auth.example.com/jwks/',
	});
	const revoked = [];
	mocks.user.auth.revokeSession = async (sessionId, uid) => {
		revoked.push({ sessionId, uid });
	};
	const { logout, restore } = loadLogout(mocks, {
		issuer: 'https://auth.example.com/application/o/nodebb/',
		sid: 'sid-1',
	});
	try {
		const res = response();
		await logout.handleBackchannelLogout({
			body: { logout_token: 'signed-token' },
			query: {},
		}, res);
		assert.equal(res.statusCode, 204);
		assert.deepEqual(revoked, [{ sessionId: 'nodebb-session-1', uid: 42 }]);
		assert.deepEqual(mocks.state.revokedSessionsForUids, []);
	} finally {
		restore();
	}
});

test('back-channel logout diagnostics record tracked session counts around revocation', async () => {
	const mocks = createMocks();
	mocks.state.subToUid.set('sub-1', 42);
	mocks.state.users.set(42, { uid: 42, username: 'linked' });
	mocks.state.settings.set('authentik-oidc', {
		backchannelLogoutEnabled: true,
		clientId: 'nodebb',
		issuer: 'https://auth.example.com/application/o/nodebb/',
		jwksUri: 'https://auth.example.com/jwks/',
	});
	const activeSessions = ['session-1'];
	mocks.user.auth.getSessions = async () => activeSessions;
	mocks.user.auth.revokeAllSessions = async (uid) => {
		mocks.state.revokedSessionsForUids.push(parseInt(uid, 10));
		activeSessions.length = 0;
	};
	const { logout, restore } = loadLogout(mocks, { sub: 'sub-1' });
	try {
		const res = response();
		await logout.handleBackchannelLogout({
			body: { logout_token: 'signed-token' },
			query: {},
		}, res);
		const diagnostics = require('../lib/diagnostics');
		const event = await diagnostics.getLastLogoutEvent();

		assert.equal(res.statusCode, 204);
		assert.equal(event.outcome, 'revoked');
		assert.equal(event.sessionsBefore, 1);
		assert.equal(event.sessionsAfter, 0);
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

test('back-channel logout diagnostics record unmatched validated token', async () => {
	const mocks = createMocks();
	mocks.state.settings.set('authentik-oidc', {
		backchannelLogoutEnabled: true,
		clientId: 'nodebb',
		issuer: 'https://auth.example.com/application/o/nodebb/',
		jwksUri: 'https://auth.example.com/jwks/',
	});
	const { logout, restore } = loadLogout(mocks, { sub: 'unknown-sub', sid: 'unknown-sid' });
	try {
		const res = response();
		await logout.handleBackchannelLogout({
			body: { logout_token: 'signed-token' },
			query: {},
		}, res);
		const diagnostics = require('../lib/diagnostics');
		const event = await diagnostics.getLastLogoutEvent();
		assert.equal(res.statusCode, 204);
		assert.equal(event.outcome, 'unmatched');
		assert.equal(event.hasSub, true);
		assert.equal(event.hasSid, true);
		assert.equal(event.uid, 0);
	} finally {
		restore();
	}
});

test('back-channel logout rejects logout tokens supplied in query string', async () => {
	const mocks = createMocks();
	mocks.state.subToUid.set('sub-1', 42);
	mocks.state.users.set(42, { uid: 42, username: 'linked' });
	mocks.state.settings.set('authentik-oidc', {
		backchannelLogoutEnabled: true,
		clientId: 'nodebb',
		issuer: 'https://auth.example.com/application/o/nodebb/',
		jwksUri: 'https://auth.example.com/jwks/',
	});
	const { logout, restore } = loadLogout(mocks, { sub: 'sub-1', jti: 'logout-1' });
	try {
		const res = response();
		await logout.handleBackchannelLogout({
			body: {},
			query: { logout_token: 'signed-token' },
			headers: {},
			readableEnded: true,
			complete: true,
		}, res);
		assert.equal(res.statusCode, 400);
		assert.deepEqual(mocks.state.revokedSessionsForUids, []);
	} finally {
		restore();
	}
});

test('back-channel logout rejects replayed logout token jti', async () => {
	const mocks = createMocks();
	mocks.state.subToUid.set('sub-1', 42);
	mocks.state.users.set(42, { uid: 42, username: 'linked' });
	mocks.state.settings.set('authentik-oidc', {
		backchannelLogoutEnabled: true,
		clientId: 'nodebb',
		issuer: 'https://auth.example.com/application/o/nodebb/',
		jwksUri: 'https://auth.example.com/jwks/',
	});
	const { logout, restore } = loadLogout(mocks, { sub: 'sub-1', jti: 'logout-1', iat: Math.floor(Date.now() / 1000) });
	try {
		const first = response();
		await logout.handleBackchannelLogout({
			body: { logout_token: 'signed-token' },
			query: {},
		}, first);
		assert.equal(first.statusCode, 204);
		assert.deepEqual(mocks.state.revokedSessionsForUids, [42]);

		const replay = response();
		await logout.handleBackchannelLogout({
			body: { logout_token: 'signed-token' },
			query: {},
		}, replay);
		assert.equal(replay.statusCode, 400);
		assert.deepEqual(mocks.state.revokedSessionsForUids, [42]);
	} finally {
		restore();
	}
});

test('back-channel logout replay claim allows only one concurrent request', async () => {
	const mocks = createMocks();
	const { logout, restore } = loadLogout(mocks, { sub: 'sub-1', jti: 'unused' });
	try {
		const results = await Promise.allSettled([
			logout.rejectReplay({ jti: 'concurrent-jti', iat: Math.floor(Date.now() / 1000) }),
			logout.rejectReplay({ jti: 'concurrent-jti', iat: Math.floor(Date.now() / 1000) }),
		]);
		assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
		assert.equal(results.filter(result => result.status === 'rejected').length, 1);
		assert.match(
			results.find(result => result.status === 'rejected').reason.message,
			/already been used/
		);
	} finally {
		restore();
	}
});

test('back-channel logout replay cache prunes expired jti entries', async () => {
	const mocks = createMocks();
	const now = Date.now();
	const { logout, restore } = loadLogout(mocks, { sub: 'sub-1', jti: 'unused' });
	try {
		await mocks.db.setObjectField(logout.USED_LOGOUT_JTI_KEY, 'expired-jti', 1);
		await mocks.db.setObjectField(logout.USED_LOGOUT_JTI_KEY, 'recent-jti', 1);
		await mocks.db.setObjectField(logout.USED_LOGOUT_JTI_AT_KEY, 'expired-jti', now - logout.LOGOUT_JTI_RETENTION_MS - 1);
		await mocks.db.setObjectField(logout.USED_LOGOUT_JTI_AT_KEY, 'recent-jti', now);

		await logout.rejectReplay({ jti: 'new-jti', iat: Math.floor(now / 1000) });
		const cache = await mocks.db.getObject(logout.USED_LOGOUT_JTI_KEY);
		const timestamps = await mocks.db.getObject(logout.USED_LOGOUT_JTI_AT_KEY);

		assert.equal(Object.prototype.hasOwnProperty.call(cache, 'expired-jti'), false);
		assert.equal(Object.prototype.hasOwnProperty.call(cache, 'recent-jti'), true);
		assert.equal(Object.prototype.hasOwnProperty.call(cache, 'new-jti'), true);
		assert.equal(Object.prototype.hasOwnProperty.call(timestamps, 'expired-jti'), false);
		assert.equal(Object.prototype.hasOwnProperty.call(timestamps, 'recent-jti'), true);
		assert.equal(Object.prototype.hasOwnProperty.call(timestamps, 'new-jti'), true);
		await assert.rejects(
			logout.rejectReplay({ jti: 'recent-jti', iat: Math.floor(now / 1000) }),
			/already been used/
		);
	} finally {
		restore();
	}
});
