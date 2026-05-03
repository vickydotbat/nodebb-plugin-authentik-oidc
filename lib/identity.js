'use strict';

const db = require.main.require('./src/database');
const user = require.main.require('./src/user');
const logger = require('./logger');
const { fail } = require('./errors');
const username = require('./username');

const SUB_TO_UID_KEY = 'authentik:sub:uid';
const EMAIL_LOOKUP_BATCH_SIZE = 500;

function normalizeEmail(email) {
	return String(email || '').trim().toLowerCase();
}

function validateClaims(claims) {
	if (!claims || typeof claims.sub !== 'string' || !claims.sub.trim()) {
		throw fail('missing-sub', 'OIDC sub is required');
	}
	const email = normalizeEmail(claims.email);
	if (!email) {
		logger.warn('missing email', { sub: claims.sub });
		throw fail('missing-email', 'OIDC email is required');
	}
	if (claims.email_verified !== true) {
		logger.warn('unverified email', { sub: claims.sub, email });
		throw fail('unverified-email', 'OIDC email must be verified');
	}
	return {
		...claims,
		sub: claims.sub.trim(),
		email,
	};
}

async function getUidBySub(sub) {
	const uid = await db.getObjectField(SUB_TO_UID_KEY, sub);
	return uid ? parseInt(uid, 10) : 0;
}

async function deleteSubMapping(sub) {
	if (typeof db.deleteObjectField === 'function') {
		await db.deleteObjectField(SUB_TO_UID_KEY, sub);
		return;
	}
	if (typeof db.deleteObjectFields === 'function') {
		await db.deleteObjectFields(SUB_TO_UID_KEY, [sub]);
	}
}

async function getUidByEmail(email) {
	const normalizedEmail = normalizeEmail(email);
	const indexedUid = await user.getUidByEmail(normalizedEmail);
	if (indexedUid) {
		return parseInt(indexedUid, 10);
	}

	const matches = [];
	let start = 0;
	while (true) {
		const uids = await db.getSortedSetRange('users:joindate', start, start + EMAIL_LOOKUP_BATCH_SIZE - 1);
		if (!uids.length) {
			break;
		}
		const users = await db.getObjectsFields(uids.map(uid => `user:${uid}`), ['uid', 'email']);
		users.forEach((userData, index) => {
			if (normalizeEmail(userData && userData.email) === normalizedEmail) {
				matches.push(parseInt(userData.uid || uids[index], 10));
			}
		});
		if (uids.length < EMAIL_LOOKUP_BATCH_SIZE) {
			break;
		}
		start += EMAIL_LOOKUP_BATCH_SIZE;
	}

	const uniqueMatches = [...new Set(matches.filter(uid => uid > 0))];
	if (uniqueMatches.length > 1) {
		logger.warn('multiple users share verified email', { email: normalizedEmail, uids: uniqueMatches });
		throw fail('email-maps-to-multiple-users', 'Verified email maps to multiple existing accounts');
	}
	return uniqueMatches[0] || 0;
}

async function linkSub(uid, claims, issuer) {
	const existingSub = await user.getUserField(uid, 'authentikSub');
	if (existingSub && existingSub !== claims.sub) {
		logger.warn('existing user has different linked sub', { uid, sub: claims.sub });
		throw fail('user-linked-to-different-sub', 'Existing account is linked to a different OIDC subject');
	}

	const currentUid = await getUidBySub(claims.sub);
	if (currentUid && currentUid !== parseInt(uid, 10)) {
		logger.warn('sub/email collision', { sub: claims.sub, subUid: currentUid, emailUid: uid });
		throw fail('sub-email-collision', 'OIDC subject is already linked to a different account');
	}

	const now = Date.now();
	await Promise.all([
		db.setObjectField(SUB_TO_UID_KEY, claims.sub, uid),
		user.setUserFields(uid, {
			authentikSub: claims.sub,
			authentikIssuer: issuer,
			authentikLinkedAt: now,
			authentikLastLoginAt: now,
			authentikLastEmail: claims.email,
		}),
	]);
}

async function resolveExistingSub(uid, claims, issuer) {
	const exists = await user.exists(uid);
	if (!exists) {
		logger.warn('sub mapping points to missing user', { uid, sub: claims.sub });
		await deleteSubMapping(claims.sub);
		return null;
	}
	const emailUid = await getUidByEmail(claims.email);
	if (emailUid && parseInt(emailUid, 10) !== parseInt(uid, 10)) {
		logger.warn('sub/email collision', { sub: claims.sub, subUid: uid, emailUid });
		throw fail('sub-email-collision', 'OIDC subject and verified email map to different accounts');
	}
	await user.setUserFields(uid, {
		authentikIssuer: issuer,
		authentikLastLoginAt: Date.now(),
		authentikLastEmail: claims.email,
	});
	logger.info('login by existing sub', { uid });
	return { uid };
}

function isUsernameTakenError(err) {
	return err && /\[\[error:username-taken\]\]|username[ -]?taken/i.test(err.message || '');
}

async function createUser(claims, issuer) {
	const baseUsername = username.baseUsername(claims);
	for (let attempt = 0; attempt < 20; attempt += 1) {
		const desiredUsername = attempt === 0 ? baseUsername : `${baseUsername}-${attempt.toString(36)}`;
		try {
			const uid = await user.create({
				username: desiredUsername,
				email: claims.email,
				fullname: claims.name || '',
			}, { emailVerification: 'verify' });
			await linkSub(uid, claims, issuer);
			logger.info('created new user', { uid });
			return { uid };
		} catch (err) {
			if (!isUsernameTakenError(err)) {
				throw err;
			}
		}
	}
	throw fail('username-unavailable', 'Unable to create a unique username');
}

async function createUserFromEmail(claims, issuer) {
	try {
		return await createUser(claims, issuer);
	} catch (err) {
		const emailUid = await getUidByEmail(claims.email);
		if (emailUid) {
			await linkSub(emailUid, claims, issuer);
			if (user.email && typeof user.email.confirmByUid === 'function') {
				await user.email.confirmByUid(emailUid);
			}
			logger.info('linked existing user by verified email after create race', { uid: emailUid });
			return { uid: emailUid };
		}
		throw err;
	}
}

async function resolve(claims, { issuer } = {}) {
	const normalized = validateClaims(claims);
	const subUid = await getUidBySub(normalized.sub);
	if (subUid) {
		const existingSubResult = await resolveExistingSub(subUid, normalized, issuer);
		if (existingSubResult) {
			return existingSubResult;
		}
	}

	const emailUid = await getUidByEmail(normalized.email);
	if (emailUid) {
		await linkSub(emailUid, normalized, issuer);
		if (user.email && typeof user.email.confirmByUid === 'function') {
			await user.email.confirmByUid(emailUid);
		}
		logger.info('linked existing user by verified email', { uid: emailUid });
		return { uid: emailUid };
	}

	return await createUserFromEmail(normalized, issuer);
}

module.exports = {
	SUB_TO_UID_KEY,
	normalizeEmail,
	validateClaims,
	getUidBySub,
	deleteSubMapping,
	getUidByEmail,
	isUsernameTakenError,
	linkSub,
	resolve,
};
