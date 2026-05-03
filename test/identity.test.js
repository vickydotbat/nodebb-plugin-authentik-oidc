'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createMocks, installNodebbMocks } = require('./bootstrap');

function loadIdentity(mocks) {
	const restore = installNodebbMocks(mocks);
	delete require.cache[require.resolve('../lib/logger')];
	delete require.cache[require.resolve('../lib/identity')];
	const identity = require('../lib/identity');
	return { identity, restore };
}

function verified(overrides = {}) {
	return {
		sub: 'sub-1',
		email: 'person@example.com',
		email_verified: true,
		preferred_username: 'person',
		name: 'Person Example',
		...overrides,
	};
}

test('new verified OIDC user creates one NodeBB user and mapping', async () => {
	const mocks = createMocks();
	const { identity, restore } = loadIdentity(mocks);
	try {
		const result = await identity.resolve(verified(), { issuer: 'https://id.example.com' });
		assert.equal(result.uid, 1);
		assert.equal(mocks.state.users.size, 1);
		assert.equal(mocks.state.subToUid.get('sub-1'), 1);
		assert.equal(mocks.state.users.get(1).authentikSub, 'sub-1');
	} finally {
		restore();
	}
});

test('same sub repeatedly resolves to same uid', async () => {
	const mocks = createMocks();
	const { identity, restore } = loadIdentity(mocks);
	try {
		const first = await identity.resolve(verified(), { issuer: 'https://id.example.com' });
		const second = await identity.resolve(verified({ email: 'person-new@example.com' }), { issuer: 'https://id.example.com' });
		assert.equal(first.uid, second.uid);
		assert.equal(mocks.state.users.size, 1);
	} finally {
		restore();
	}
});

test('existing user with same verified email links without duplicate', async () => {
	const mocks = createMocks();
	mocks.state.users.set(42, { uid: 42, username: 'local', email: 'person@example.com' });
	mocks.state.emailToUid.set('person@example.com', 42);
	const { identity, restore } = loadIdentity(mocks);
	try {
		const result = await identity.resolve(verified(), { issuer: 'https://id.example.com' });
		assert.equal(result.uid, 42);
		assert.equal(mocks.state.users.size, 1);
		assert.equal(mocks.state.subToUid.get('sub-1'), 42);
	} finally {
		restore();
	}
});

test('unverified email rejects without creating or linking', async () => {
	const mocks = createMocks();
	const { identity, restore } = loadIdentity(mocks);
	try {
		await assert.rejects(
			identity.resolve(verified({ email_verified: false }), { issuer: 'https://id.example.com' }),
			/email must be verified/
		);
		assert.equal(mocks.state.users.size, 0);
		assert.equal(mocks.state.subToUid.size, 0);
	} finally {
		restore();
	}
});

test('username conflict creates safe unique username', async () => {
	const mocks = createMocks();
	mocks.state.users.set(7, { uid: 7, username: 'person' });
	const { identity, restore } = loadIdentity(mocks);
	try {
		const result = await identity.resolve(verified({ email: 'other@example.com' }), { issuer: 'https://id.example.com' });
		assert.equal(mocks.state.users.get(result.uid).username, 'person-1');
	} finally {
		restore();
	}
});

test('sub mapped to uid A but verified email belongs to uid B fails safely', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, { uid: 1, username: 'a', email: 'a@example.com' });
	mocks.state.users.set(2, { uid: 2, username: 'b', email: 'person@example.com' });
	mocks.state.emailToUid.set('person@example.com', 2);
	mocks.state.subToUid.set('sub-1', 1);
	const { identity, restore } = loadIdentity(mocks);
	try {
		await assert.rejects(
			identity.resolve(verified(), { issuer: 'https://id.example.com' }),
			/different accounts/
		);
	} finally {
		restore();
	}
});

test('missing email fails safely', async () => {
	const mocks = createMocks();
	const { identity, restore } = loadIdentity(mocks);
	try {
		await assert.rejects(
			identity.resolve(verified({ email: '' }), { issuer: 'https://id.example.com' }),
			/email is required/
		);
		assert.equal(mocks.state.users.size, 0);
	} finally {
		restore();
	}
});

test('string email_verified does not pass strict validation', async () => {
	const mocks = createMocks();
	const { identity, restore } = loadIdentity(mocks);
	try {
		await assert.rejects(
			identity.resolve(verified({ email_verified: 'true' }), { issuer: 'https://id.example.com' }),
			/email must be verified/
		);
	} finally {
		restore();
	}
});
