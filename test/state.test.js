'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

function loadStateStore(openidClient) {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'openid-client') {
			return openidClient;
		}
		return originalLoad.call(this, request, parent, isMain);
	};
	delete require.cache[require.resolve('../lib/state')];
	const stateStore = require('../lib/state');
	return {
		stateStore,
		restore() {
			Module._load = originalLoad;
			delete require.cache[require.resolve('../lib/state')];
		},
	};
}

test('state creation delegates state, nonce, and PKCE primitives to openid-client', async () => {
	const calls = [];
	const { stateStore, restore } = loadStateStore({
		randomState() {
			calls.push('randomState');
			return 'library-state';
		},
		randomNonce() {
			calls.push('randomNonce');
			return 'library-nonce';
		},
		randomPKCECodeVerifier() {
			calls.push('randomPKCECodeVerifier');
			return 'library-code-verifier';
		},
		async calculatePKCECodeChallenge(verifier) {
			calls.push(['calculatePKCECodeChallenge', verifier]);
			return 'library-code-challenge';
		},
	});
	const req = { session: {} };
	try {
		const stateData = await stateStore.create(req);
		assert.deepEqual(calls, [
			'randomState',
			'randomNonce',
			'randomPKCECodeVerifier',
			['calculatePKCECodeChallenge', 'library-code-verifier'],
		]);
		assert.equal(stateData.state, 'library-state');
		assert.equal(stateData.nonce, 'library-nonce');
		assert.equal(stateData.codeVerifier, 'library-code-verifier');
		assert.equal(stateData.codeChallenge, 'library-code-challenge');
		assert.equal(Object.prototype.hasOwnProperty.call(req.session.authentikOidc, stateData.state), true);
	} finally {
		restore();
	}
});

const stateStore = require('../lib/state');

test('state consumption rejects missing callback state', () => {
	const req = { session: {} };
	assert.throws(
		() => stateStore.consume(req, undefined),
		/Missing OIDC state/
	);
});

test('state consumption is single use', async () => {
	const req = { session: {} };
	const stateData = await stateStore.create(req);
	assert.equal(stateStore.consume(req, stateData.state).nonce, stateData.nonce);
	assert.throws(
		() => stateStore.consume(req, stateData.state),
		/Missing OIDC state/
	);
});

test('state creation ignores caller supplied state and always uses PKCE', async () => {
	const req = { session: {} };
	const first = await stateStore.create(req, 'fixed-state', { usePkce: false });
	const second = await stateStore.create(req, 'fixed-state', { usePkce: false });

	assert.notEqual(first.state, 'fixed-state');
	assert.notEqual(second.state, 'fixed-state');
	assert.notEqual(first.state, second.state);
	assert.equal(typeof first.codeVerifier, 'string');
	assert.equal(first.codeVerifier.length > 40, true);
	assert.equal(typeof second.codeVerifier, 'string');
	assert.equal(second.codeVerifier.length > 40, true);
	assert.equal(Object.keys(req.session.authentikOidc).length, 2);
});

test('state from another browser session is rejected', async () => {
	const attackerReq = { session: {} };
	const victimReq = { session: {} };
	const attackerState = (await stateStore.create(attackerReq)).state;

	assert.throws(
		() => stateStore.consume(victimReq, attackerState),
		/Missing OIDC state/
	);
	assert.equal(Object.prototype.hasOwnProperty.call(attackerReq.session.authentikOidc, attackerState), true);
});
