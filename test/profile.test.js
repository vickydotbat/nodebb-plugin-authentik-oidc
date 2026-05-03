'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createMocks, installNodebbMocks } = require('./bootstrap');

function loadProfile(mocks) {
	const restore = installNodebbMocks(mocks);
	delete require.cache[require.resolve('../lib/profile')];
	const profile = require('../lib/profile');
	return { profile, restore };
}

test('linked account state exposes safe user-facing metadata only', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, {
		uid: 1,
		username: 'linked',
		authentikSub: 'sub-secret-value',
		authentikIssuer: 'https://auth.example.com/application/o/nodebb/',
		authentikLinkedAt: 1710000000000,
		authentikLastLoginAt: 1710000100000,
		authentikLastEmail: 'linked@example.com',
	});
	const { profile, restore } = loadProfile(mocks);
	try {
		const state = await profile.getLinkedAccountState(1, {
			displayName: 'Account Gate',
			selfServiceProfileUrl: 'https://auth.example.com/if/user/#/settings',
			selfServicePasswordUrl: '',
			selfServiceMfaUrl: 'https://auth.example.com/if/user/#/settings;page=mfa',
			selfServiceSessionsUrl: '',
		});
		assert.equal(state.linked, true);
		assert.equal(state.providerName, 'Account Gate');
		assert.equal(state.issuer, 'https://auth.example.com/application/o/nodebb/');
		assert.equal(state.lastProviderEmail, 'linked@example.com');
		assert.equal(state.linkedAt, '2024-03-09T16:00:00.000Z');
		assert.equal(state.lastLoginAt, '2024-03-09T16:01:40.000Z');
		assert.equal(state.hasExternalLinks, true);
		assert.deepEqual(state.externalLinks.map(link => link.id), ['profile', 'mfa']);
		assert.equal(Object.prototype.hasOwnProperty.call(state, 'sub'), false);
		assert.equal(JSON.stringify(state).includes('sub-secret-value'), false);
	} finally {
		restore();
	}
});

test('unlinked account state is read-only and has no provider actions by default', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, {
		uid: 1,
		username: 'local',
	});
	const { profile, restore } = loadProfile(mocks);
	try {
		const state = await profile.getLinkedAccountState(1, {});
		assert.equal(state.linked, false);
		assert.equal(state.providerName, 'Authentik');
		assert.equal(state.hasExternalLinks, false);
		assert.deepEqual(state.externalLinks, []);
		assert.deepEqual(state.managedFields, []);
	} finally {
		restore();
	}
});

test('profile menu item is self-only', async () => {
	const mocks = createMocks();
	const { profile, restore } = loadProfile(mocks);
	try {
		const data = await profile.addProfileMenuItem({ links: [] });
		assert.equal(data.links.length, 1);
		assert.equal(data.links[0].route, 'authentik-oidc');
		assert.equal(data.links[0].visibility.self, true);
		assert.equal(data.links[0].visibility.other, false);
		assert.equal(data.links[0].visibility.admin, false);
	} finally {
		restore();
	}
});
