'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const stateStore = require('../lib/state');

test('state creation generates a cryptographic state when caller does not provide one', () => {
	const req = { session: {} };
	const stateData = stateStore.create(req, undefined, { usePkce: true });
	assert.equal(typeof stateData.state, 'string');
	assert.equal(stateData.state.length > 20, true);
	assert.equal(Object.prototype.hasOwnProperty.call(req.session.authentikOidc, stateData.state), true);
	assert.equal(typeof stateData.nonce, 'string');
	assert.equal(typeof stateData.codeChallenge, 'string');
});

test('state consumption rejects missing callback state', () => {
	const req = { session: {} };
	assert.throws(
		() => stateStore.consume(req, undefined),
		/Missing OIDC state/
	);
});

test('state consumption is single use', () => {
	const req = { session: {} };
	const stateData = stateStore.create(req, 'state-1', { usePkce: false });
	assert.equal(stateStore.consume(req, stateData.state).nonce, stateData.nonce);
	assert.throws(
		() => stateStore.consume(req, stateData.state),
		/Missing OIDC state/
	);
});
