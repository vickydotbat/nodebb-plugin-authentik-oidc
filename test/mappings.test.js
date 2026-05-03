'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createMocks, installNodebbMocks } = require('./bootstrap');

function loadMappings(mocks) {
	const restore = installNodebbMocks(mocks);
	delete require.cache[require.resolve('../lib/logger')];
	delete require.cache[require.resolve('../lib/identity')];
	delete require.cache[require.resolve('../lib/mappings')];
	const mappings = require('../lib/mappings');
	return { mappings, restore };
}

test('mapping audit reports healthy linked mappings', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, {
		uid: 1,
		username: 'linked',
		email: 'linked@example.com',
		authentikSub: 'sub-1',
	});
	mocks.state.subToUid.set('sub-1', 1);
	const { mappings, restore } = loadMappings(mocks);
	try {
		const result = await mappings.audit();
		assert.deepEqual(result.summary, {
			mappings: 1,
			linkedUsers: 1,
			staleMappings: 0,
			reverseMissing: 0,
			reverseConflicts: 0,
			duplicateUserLinks: 0,
		});
	} finally {
		restore();
	}
});

test('mapping audit reports stale mappings and repair removes only stale entries', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, {
		uid: 1,
		username: 'linked',
		email: 'linked@example.com',
		authentikSub: 'sub-1',
	});
	mocks.state.subToUid.set('sub-1', 1);
	mocks.state.subToUid.set('deleted-sub', 99);
	const { mappings, restore } = loadMappings(mocks);
	try {
		const result = await mappings.audit();
		assert.equal(result.summary.staleMappings, 1);
		assert.deepEqual(result.staleMappings, [{ sub: 'deleted-sub', uid: 99 }]);

		await assert.rejects(
			mappings.repairStaleMappings(),
			/explicit confirmation/
		);

		const repair = await mappings.repairStaleMappings({ confirm: true });
		assert.equal(repair.removed, 1);
		assert.equal(mocks.state.subToUid.has('deleted-sub'), false);
		assert.equal(mocks.state.subToUid.get('sub-1'), 1);
	} finally {
		restore();
	}
});

test('mapping audit reports missing reverse mappings and user-side duplicate subjects', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, {
		uid: 1,
		username: 'one',
		email: 'one@example.com',
		authentikSub: 'shared-sub',
	});
	mocks.state.users.set(2, {
		uid: 2,
		username: 'two',
		email: 'two@example.com',
		authentikSub: 'shared-sub',
	});
	mocks.state.users.set(3, {
		uid: 3,
		username: 'missing',
		email: 'missing@example.com',
		authentikSub: 'missing-sub',
	});
	mocks.state.subToUid.set('shared-sub', 1);
	const { mappings, restore } = loadMappings(mocks);
	try {
		const result = await mappings.audit();
		assert.equal(result.summary.duplicateUserLinks, 1);
		assert.equal(result.duplicateUserLinks[0].sub, 'shared-sub');
		assert.equal(result.duplicateUserLinks[0].users.length, 2);
		assert.equal(result.summary.reverseMissing, 1);
		assert.equal(result.reverseMissing[0].sub, 'missing-sub');
		assert.equal(result.summary.reverseConflicts, 1);
		assert.equal(result.reverseConflicts[0].uid, 2);
		assert.equal(result.reverseConflicts[0].mappedUid, 1);
	} finally {
		restore();
	}
});
