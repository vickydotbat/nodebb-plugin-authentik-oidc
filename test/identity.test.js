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

function loadIdentityInstances(mocks, count) {
	const restore = installNodebbMocks(mocks);
	delete require.cache[require.resolve('../lib/logger')];
	const identities = [];
	for (let i = 0; i < count; i += 1) {
		delete require.cache[require.resolve('../lib/identity')];
		identities.push(require('../lib/identity'));
	}
	return { identities, restore };
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
		assert.equal(mocks.state.directSubToUid.get('sub-1'), 1);
		assert.equal(mocks.state.users.get(1).authentikSub, 'sub-1');
	} finally {
		restore();
	}
});

test('new verified OIDC user does not inherit existing account avatar fields', async () => {
	const mocks = createMocks();
	const { identity, restore } = loadIdentity(mocks);
	try {
		const existingUid = await mocks.user.create({
			username: 'archvillainette',
			email: 'arch@example.com',
			picture: 'https://forum.example.com/assets/uploads/profile/avatar.png',
			uploadedpicture: '/assets/uploads/profile/avatar.png',
			'icon:text': 'A',
			'icon:bgColor': '#123456',
			aboutme: 'existing user bio',
			signature: 'existing signature',
			'cover:url': '/assets/uploads/profile/cover.png',
		});
		const originalCreate = mocks.user.create;
		mocks.user.create = async (data, opts) => {
			const uid = await originalCreate(data, opts);
			Object.assign(mocks.state.users.get(uid), {
				picture: 'https://forum.example.com/assets/uploads/profile/avatar.png',
				uploadedpicture: '/assets/uploads/profile/avatar.png',
				'icon:text': 'A',
				'icon:bgColor': '#123456',
				aboutme: 'existing user bio',
				signature: 'existing signature',
				'cover:url': '/assets/uploads/profile/cover.png',
			});
			return uid;
		};
		const result = await identity.resolve(verified({
			sub: 'new-authentik-user',
			email: 'new@example.com',
			preferred_username: 'new-user',
			picture: 'https://auth.example.com/avatar/current-session.png',
		}), { issuer: 'https://id.example.com' });
		assert.notEqual(result.uid, existingUid);
		const created = mocks.state.users.get(result.uid);
		assert.equal(created.picture, '');
		assert.equal(created.uploadedpicture, '');
		assert.equal(created['icon:text'], '');
		assert.equal(created['icon:bgColor'], '');
		assert.equal(created.aboutme, '');
		assert.equal(created.signature, '');
		assert.equal(created['cover:url'], '');
		assert.equal(created.fullname, 'Person Example');
		assert.equal(mocks.state.users.get(existingUid).picture, 'https://forum.example.com/assets/uploads/profile/avatar.png');
		assert.equal(mocks.state.users.get(existingUid).aboutme, 'existing user bio');
	} finally {
		restore();
	}
});

test('new verified OIDC user does not inherit avatar fields from current NodeBB session user', async () => {
	const mocks = createMocks();
	const { identity, restore } = loadIdentity(mocks);
	try {
		const sessionUid = await mocks.user.create({
			username: 'active-local-user',
			email: 'active@example.com',
			picture: 'https://forum.example.com/assets/uploads/profile/session-avatar.png',
			uploadedpicture: '/assets/uploads/profile/session-avatar.png',
			'icon:text': 'S',
			'icon:bgColor': '#654321',
			aboutme: 'session user bio',
		});
		const originalCreate = mocks.user.create;
		mocks.user.create = async (data, opts) => {
			const uid = await originalCreate(data, opts);
			Object.assign(mocks.state.users.get(uid), {
				picture: mocks.state.users.get(sessionUid).picture,
				uploadedpicture: mocks.state.users.get(sessionUid).uploadedpicture,
				'icon:text': mocks.state.users.get(sessionUid)['icon:text'],
				'icon:bgColor': mocks.state.users.get(sessionUid)['icon:bgColor'],
				aboutme: mocks.state.users.get(sessionUid).aboutme,
			});
			return uid;
		};
		const result = await identity.resolve(verified({
			sub: 'new-session-isolated-user',
			email: 'isolated@example.com',
			preferred_username: 'isolated',
		}), { issuer: 'https://id.example.com' });
		assert.notEqual(result.uid, sessionUid);
		const created = mocks.state.users.get(result.uid);
		assert.equal(created.picture, '');
		assert.equal(created.uploadedpicture, '');
		assert.equal(created['icon:text'], '');
		assert.equal(created['icon:bgColor'], '');
		assert.equal(created.aboutme, '');
		assert.equal(mocks.state.users.get(sessionUid).picture, 'https://forum.example.com/assets/uploads/profile/session-avatar.png');
	} finally {
		restore();
	}
});

test('verified-email link to existing NodeBB account preserves existing avatar fields', async () => {
	const mocks = createMocks();
	const existingUid = await mocks.user.create({
		username: 'archvillainette',
		email: 'person@example.com',
		picture: 'https://forum.example.com/assets/uploads/profile/avatar.png',
		uploadedpicture: '/assets/uploads/profile/avatar.png',
		'icon:text': 'A',
		'icon:bgColor': '#123456',
		aboutme: 'existing user bio',
	});
	const { identity, restore } = loadIdentity(mocks);
	try {
		const result = await identity.resolve(verified(), { issuer: 'https://id.example.com' });
		assert.equal(result.uid, existingUid);
		const linked = mocks.state.users.get(existingUid);
		assert.equal(linked.picture, 'https://forum.example.com/assets/uploads/profile/avatar.png');
		assert.equal(linked.uploadedpicture, '/assets/uploads/profile/avatar.png');
		assert.equal(linked['icon:text'], 'A');
		assert.equal(linked['icon:bgColor'], '#123456');
		assert.equal(linked.aboutme, 'existing user bio');
		assert.equal(linked.authentikSub, 'sub-1');
	} finally {
		restore();
	}
});

test('direct subject key resolves existing linked user for spec-compatible storage', async () => {
	const mocks = createMocks();
	mocks.state.users.set(42, {
		uid: 42,
		username: 'linked',
		email: 'person@example.com',
		authentikSub: 'sub-1',
	});
	mocks.state.emailToUid.set('person@example.com', 42);
	mocks.state.directSubToUid.set('sub-1', 42);
	const { identity, restore } = loadIdentity(mocks);
	try {
		const result = await identity.resolve(verified(), { issuer: 'https://id.example.com' });
		assert.equal(result.uid, 42);
		assert.equal(mocks.state.users.size, 1);
	} finally {
		restore();
	}
});

test('subject mapping storage conflict fails safely', async () => {
	const mocks = createMocks();
	mocks.state.subToUid.set('sub-1', 1);
	mocks.state.directSubToUid.set('sub-1', 2);
	const { identity, restore } = loadIdentity(mocks);
	try {
		await assert.rejects(
			identity.getUidBySub('sub-1'),
			/mapping storage is inconsistent/
		);
	} finally {
		restore();
	}
});

test('login stores OIDC sid for back-channel logout mapping', async () => {
	const mocks = createMocks();
	const { identity, restore } = loadIdentity(mocks);
	try {
		const result = await identity.resolve(verified({ sid: 'session-1' }), { issuer: 'https://id.example.com' });
		assert.equal(result.uid, 1);
		assert.equal(mocks.state.sidToUid.get('session-1'), 1);
		assert.equal(await identity.getUidBySid('session-1'), 1);
		assert.equal(mocks.state.users.get(1).authentikLastSid, 'session-1');
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

test('concurrent verified-email links with different subjects fail closed', async () => {
	const mocks = createMocks();
	mocks.state.users.set(42, { uid: 42, username: 'local', email: 'person@example.com' });
	mocks.state.emailToUid.set('person@example.com', 42);
	const { identity, restore } = loadIdentity(mocks);
	try {
		const results = await Promise.allSettled([
			identity.resolve(verified({ sub: 'sub-1' }), { issuer: 'https://id.example.com' }),
			identity.resolve(verified({ sub: 'sub-2' }), { issuer: 'https://id.example.com' }),
		]);
		assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
		assert.equal(results.filter(result => result.status === 'rejected').length, 1);
		assert.match(
			results.find(result => result.status === 'rejected').reason.message,
			/different OIDC subject|concurrent/i
		);
		assert.equal([...mocks.state.subToUid.keys()].length, 1);
		assert.equal(mocks.state.users.get(42).authentikSub, [...mocks.state.subToUid.keys()][0]);
	} finally {
		restore();
	}
});

test('concurrent verified-email links from separate module instances fail closed', async () => {
	const mocks = createMocks();
	mocks.state.users.set(42, { uid: 42, username: 'local', email: 'person@example.com' });
	mocks.state.emailToUid.set('person@example.com', 42);
	const { identities, restore } = loadIdentityInstances(mocks, 2);
	try {
		const results = await Promise.allSettled([
			identities[0].resolve(verified({ sub: 'sub-1' }), { issuer: 'https://id.example.com' }),
			identities[1].resolve(verified({ sub: 'sub-2' }), { issuer: 'https://id.example.com' }),
		]);
		assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
		assert.equal(results.filter(result => result.status === 'rejected').length, 1);
		assert.match(
			results.find(result => result.status === 'rejected').reason.message,
			/different OIDC subject|concurrent/i
		);
		assert.equal([...mocks.state.subToUid.keys()].length, 1);
		assert.equal(mocks.state.users.get(42).authentikSub, [...mocks.state.subToUid.keys()][0]);
	} finally {
		restore();
		delete require.cache[require.resolve('../lib/identity')];
	}
});

test('existing user with same unindexed email links without duplicate', async () => {
	const mocks = createMocks();
	mocks.state.users.set(42, {
		uid: 42,
		username: 'archvillainette',
		email: 'person@example.com',
		'email:confirmed': 0,
	});
	const { identity, restore } = loadIdentity(mocks);
	try {
		const result = await identity.resolve(verified(), { issuer: 'https://id.example.com' });
		assert.equal(result.uid, 42);
		assert.equal(mocks.state.users.size, 1);
		assert.equal(mocks.state.subToUid.get('sub-1'), 42);
		assert.equal(mocks.state.emailToUid.get('person@example.com'), 42);
		assert.equal(mocks.state.users.get(42)['email:confirmed'], 1);
	} finally {
		restore();
	}
});

test('multiple existing users with same unindexed email fail safely', async () => {
	const mocks = createMocks();
	mocks.state.users.set(42, { uid: 42, username: 'a', email: 'person@example.com' });
	mocks.state.users.set(43, { uid: 43, username: 'b', email: 'PERSON@example.com' });
	const { identity, restore } = loadIdentity(mocks);
	try {
		await assert.rejects(
			identity.resolve(verified(), { issuer: 'https://id.example.com' }),
			/multiple existing accounts/
		);
		assert.equal(mocks.state.subToUid.size, 0);
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

test('existing sub with unverified changed email still resolves by sub without linking email', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, {
		uid: 1,
		username: 'linked',
		email: 'person@example.com',
		authentikSub: 'sub-1',
	});
	mocks.state.emailToUid.set('person@example.com', 1);
	mocks.state.subToUid.set('sub-1', 1);
	const { identity, restore } = loadIdentity(mocks);
	try {
		const result = await identity.resolve(verified({
			email: 'changed-unverified@example.com',
			email_verified: false,
		}), { issuer: 'https://id.example.com' });
		assert.equal(result.uid, 1);
		assert.equal(mocks.state.emailToUid.has('changed-unverified@example.com'), false);
		assert.equal(mocks.state.users.size, 1);
	} finally {
		restore();
	}
});

test('existing sub with unverified email belonging to another uid fails safely', async () => {
	const mocks = createMocks();
	mocks.state.users.set(1, {
		uid: 1,
		username: 'linked',
		email: 'person@example.com',
		authentikSub: 'sub-1',
	});
	mocks.state.users.set(2, {
		uid: 2,
		username: 'other',
		email: 'other@example.com',
	});
	mocks.state.emailToUid.set('person@example.com', 1);
	mocks.state.emailToUid.set('other@example.com', 2);
	mocks.state.subToUid.set('sub-1', 1);
	const { identity, restore } = loadIdentity(mocks);
	try {
		await assert.rejects(
			identity.resolve(verified({
				email: 'other@example.com',
				email_verified: false,
			}), { issuer: 'https://id.example.com' }),
			/different accounts/
		);
		assert.equal(mocks.state.subToUid.get('sub-1'), 1);
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

test('username conflict detected by create retries with safe unique username', async () => {
	const mocks = createMocks();
	mocks.state.users.set(7, { uid: 7, username: 'Person' });
	const { identity, restore } = loadIdentity(mocks);
	try {
		const result = await identity.resolve(verified({ email: 'other@example.com' }), { issuer: 'https://id.example.com' });
		assert.equal(mocks.state.users.get(result.uid).username, 'person-1');
	} finally {
		restore();
	}
});

test('username collision reject policy fails new SSO account creation', async () => {
	const mocks = createMocks();
	mocks.state.users.set(7, { uid: 7, username: 'Person' });
	const { identity, restore } = loadIdentity(mocks);
	try {
		await assert.rejects(
			identity.resolve(
				verified({ email: 'other@example.com' }),
				{ issuer: 'https://id.example.com', usernameCollisionPolicy: 'reject' }
			),
			/preferred username is already unavailable/
		);
		assert.equal(mocks.state.users.size, 1);
		assert.equal(mocks.state.subToUid.size, 0);
	} finally {
		restore();
	}
});

test('account creation disabled rejects new verified SSO user without mapping', async () => {
	const mocks = createMocks();
	const { identity, restore } = loadIdentity(mocks);
	try {
		await assert.rejects(
			identity.resolve(
				verified({ email: 'new@example.com' }),
				{ issuer: 'https://id.example.com', allowAccountCreation: false }
			),
			/SSO account creation is disabled/
		);
		assert.equal(mocks.state.users.size, 0);
		assert.equal(mocks.state.subToUid.size, 0);
	} finally {
		restore();
	}
});

test('account creation disabled still links existing verified email', async () => {
	const mocks = createMocks();
	mocks.state.users.set(42, { uid: 42, username: 'local', email: 'person@example.com' });
	mocks.state.emailToUid.set('person@example.com', 42);
	const { identity, restore } = loadIdentity(mocks);
	try {
		const result = await identity.resolve(
			verified(),
			{ issuer: 'https://id.example.com', allowAccountCreation: false }
		);
		assert.equal(result.uid, 42);
		assert.equal(mocks.state.users.size, 1);
		assert.equal(mocks.state.subToUid.get('sub-1'), 42);
	} finally {
		restore();
	}
});

test('email race during user creation links existing verified email without duplicate', async () => {
	const mocks = createMocks();
	let createdDuringRace = false;
	const originalCreate = mocks.user.create;
	mocks.user.create = async (data, opts) => {
		if (!createdDuringRace) {
			createdDuringRace = true;
			mocks.state.users.set(42, { uid: 42, username: 'race', email: data.email });
			mocks.state.emailToUid.set(data.email.toLowerCase(), 42);
			throw new Error('[[error:email-taken]]');
		}
		return await originalCreate(data, opts);
	};
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

test('stale sub mapping to deleted user is removed and verified email can link', async () => {
	const mocks = createMocks();
	mocks.state.users.set(42, { uid: 42, username: 'archvillainette', email: 'person@example.com' });
	mocks.state.emailToUid.set('person@example.com', 42);
	mocks.state.subToUid.set('sub-1', 99);
	const { identity, restore } = loadIdentity(mocks);
	try {
		const result = await identity.resolve(verified(), { issuer: 'https://id.example.com' });
		assert.equal(result.uid, 42);
		assert.equal(mocks.state.subToUid.get('sub-1'), 42);
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
