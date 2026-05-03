'use strict';

const db = require.main.require('./src/database');
const user = require.main.require('./src/user');
const logger = require('./logger');
const identity = require('./identity');

const USER_SCAN_BATCH_SIZE = 500;

async function getSubMappings() {
	if (typeof db.getObject !== 'function') {
		throw new Error('NodeBB database adapter does not support object audit reads');
	}
	const mappings = await db.getObject(identity.SUB_TO_UID_KEY);
	return mappings || {};
}

function normalizeUid(uid) {
	const parsed = parseInt(uid, 10);
	return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

async function scanLinkedUsers() {
	const linkedUsers = [];
	let start = 0;
	while (true) {
		const uids = await db.getSortedSetRange('users:joindate', start, start + USER_SCAN_BATCH_SIZE - 1);
		if (!uids.length) {
			break;
		}
		const users = await db.getObjectsFields(
			uids.map(uid => `user:${uid}`),
			['uid', 'username', 'authentikSub']
		);
		users.forEach((userData, index) => {
			if (userData && userData.authentikSub) {
				linkedUsers.push({
					uid: normalizeUid(userData.uid || uids[index]),
					username: userData.username || '',
					sub: String(userData.authentikSub),
				});
			}
		});
		if (uids.length < USER_SCAN_BATCH_SIZE) {
			break;
		}
		start += USER_SCAN_BATCH_SIZE;
	}
	return linkedUsers;
}

async function audit() {
	const mappings = await getSubMappings();
	const entries = Object.entries(mappings).map(([sub, uid]) => ({
		sub,
		uid: normalizeUid(uid),
	}));
	const mappedBySub = new Map(entries.map(entry => [entry.sub, entry.uid]));
	const usersBySub = new Map();
	const linkedUsers = await scanLinkedUsers();

	linkedUsers.forEach((linkedUser) => {
		if (!usersBySub.has(linkedUser.sub)) {
			usersBySub.set(linkedUser.sub, []);
		}
		usersBySub.get(linkedUser.sub).push(linkedUser);
	});

	const staleMappings = [];
	const reverseMissing = [];
	const reverseConflicts = [];
	const duplicateUserLinks = [];

	await Promise.all(entries.map(async (entry) => {
		const exists = entry.uid ? await user.exists(entry.uid) : false;
		if (!exists) {
			staleMappings.push(entry);
			return;
		}
		const userSub = await user.getUserField(entry.uid, 'authentikSub');
		if (!userSub) {
			reverseMissing.push(entry);
		} else if (userSub !== entry.sub) {
			reverseConflicts.push({
				...entry,
				userSub,
			});
		}
	}));

	usersBySub.forEach((users, sub) => {
		if (users.length > 1) {
			duplicateUserLinks.push({ sub, users });
		}
		const mappedUid = mappedBySub.get(sub);
		users.forEach((linkedUser) => {
			if (!mappedUid) {
				reverseMissing.push({
					sub,
					uid: linkedUser.uid,
					username: linkedUser.username,
				});
			} else if (mappedUid !== linkedUser.uid) {
				reverseConflicts.push({
					sub,
					uid: linkedUser.uid,
					username: linkedUser.username,
					mappedUid,
				});
			}
		});
	});

	const summary = {
		mappings: entries.length,
		linkedUsers: linkedUsers.length,
		staleMappings: staleMappings.length,
		reverseMissing: reverseMissing.length,
		reverseConflicts: reverseConflicts.length,
		duplicateUserLinks: duplicateUserLinks.length,
	};

	return {
		summary,
		staleMappings: staleMappings.sort((a, b) => a.sub.localeCompare(b.sub)),
		reverseMissing,
		reverseConflicts,
		duplicateUserLinks,
	};
}

async function repairStaleMappings({ confirm } = {}) {
	if (confirm !== true) {
		const err = new Error('Stale mapping repair requires explicit confirmation');
		err.statusCode = 400;
		throw err;
	}
	const result = await audit();
	await Promise.all(result.staleMappings.map(entry => identity.deleteSubMapping(entry.sub)));
	if (result.staleMappings.length) {
		logger.warn('removed stale sub mappings', { count: result.staleMappings.length });
	}
	return {
		removed: result.staleMappings.length,
		staleMappings: result.staleMappings,
		summary: {
			...result.summary,
			staleMappings: 0,
			mappings: result.summary.mappings - result.staleMappings.length,
		},
	};
}

module.exports = {
	audit,
	repairStaleMappings,
};
