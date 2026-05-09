'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createMocks, installNodebbMocks } = require('./bootstrap');

function loadSync(mocks) {
	const restore = installNodebbMocks(mocks);
	delete require.cache[require.resolve('../lib/sync')];
	const sync = require('../lib/sync');
	return { sync, restore };
}

test('profile sync updates fullname only when explicitly enabled', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, {
		uid: 1,
		username: 'linked',
		fullname: 'Local Name',
	});
	const { sync, restore } = loadSync(mocks);
	try {
		const skipped = await sync.syncProfile(1, { name: 'Provider Name' }, {});
		assert.deepEqual(skipped.updatedFields, []);
		assert.equal(mocks.state.users.get(1).fullname, 'Local Name');
		assert.equal(mocks.state.users.get(1).authentikLastSyncedAt, undefined);

		const updated = await sync.syncProfile(1, { name: ' Provider Name ' }, { syncFullnameOnLogin: true });
		assert.deepEqual(updated.updatedFields, ['fullname']);
		assert.deepEqual(updated.managedFields, ['fullname']);
		assert.equal(mocks.state.users.get(1).fullname, 'Provider Name');
		assert.equal(typeof mocks.state.users.get(1).authentikLastSyncedAt, 'number');
	} finally {
		restore();
	}
});

test('profile sync does not blank fullname when provider omits name claim', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, {
		uid: 1,
		username: 'linked',
		fullname: 'Local Name',
	});
	const { sync, restore } = loadSync(mocks);
	try {
		const result = await sync.syncProfile(1, { name: '' }, { syncFullnameOnLogin: true });
		assert.deepEqual(result.updatedFields, []);
		assert.deepEqual(result.managedFields, ['fullname']);
		assert.equal(mocks.state.users.get(1).fullname, 'Local Name');
		assert.equal(mocks.state.users.get(1).authentikLastSyncedAt, undefined);
	} finally {
		restore();
	}
});

test('profile sync rejects reserved staff-like fullnames for normal users', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, {
		uid: 1,
		username: 'linked',
		fullname: 'Local Name',
	});
	const { sync, restore } = loadSync(mocks);
	try {
		const result = await sync.syncProfile(1, { name: 'Admin' }, { syncFullnameOnLogin: true });
		assert.deepEqual(result.updatedFields, []);
		assert.deepEqual(result.skippedFields, ['fullname']);
		assert.equal(mocks.state.users.get(1).fullname, 'Local Name');
	} finally {
		restore();
	}
});

test('profile sync allows reserved staff-like fullnames for privileged users only', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, {
		uid: 1,
		username: 'linked',
		fullname: 'Local Name',
		isAdmin: 1,
	});
	const { sync, restore } = loadSync(mocks);
	try {
		const result = await sync.syncProfile(1, { name: 'Admin' }, { syncFullnameOnLogin: true });
		assert.deepEqual(result.updatedFields, ['fullname']);
		assert.equal(mocks.state.users.get(1).fullname, 'Admin');
	} finally {
		restore();
	}
});
