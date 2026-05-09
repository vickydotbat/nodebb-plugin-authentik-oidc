'use strict';

const crypto = require('node:crypto');
const db = require.main.require('./src/database');
const user = require.main.require('./src/user');
const logger = require('./logger');
const { fail } = require('./errors');
const username = require('./username');

const SUB_TO_UID_KEY = 'authentik:sub:uid';
const ISSUER_SUB_TO_UID_KEY = 'authentik:issuer-sub:uid';
const SID_TO_UID_KEY = 'authentik:sid:uid';
const LINK_LOCK_KEY = 'authentik:link-lock:uid';
const LINK_LOCK_AT_KEY = 'authentik:link-lock-at:uid';
const LINK_LOCK_TTL_MS = 2 * 60 * 1000;
const EMAIL_LOOKUP_BATCH_SIZE = 500;
const NEW_USER_PROFILE_ISOLATION_FIELDS = [
	'picture',
	'uploadedpicture',
	'icon:text',
	'icon:bgColor',
	'cover:url',
	'cover:position',
	'aboutme',
	'signature',
	'website',
	'location',
	'birthday',
];
let linkTail = Promise.resolve();

function subKey(sub) {
	return `authentik:sub:${sub}`;
}

function issuerSubjectField(issuer, sub) {
	return crypto.createHash('sha256')
		.update(`${issuer || ''}\x1f${sub || ''}`)
		.digest('hex');
}

function issuerSubjectKey(issuer, sub) {
	return `authentik:issuer-sub:${issuerSubjectField(issuer, sub)}`;
}

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
	return {
		...claims,
		sub: claims.sub.trim(),
		email,
		emailVerified: claims.email_verified === true,
		sid: typeof claims.sid === 'string' && claims.sid.trim() ? claims.sid.trim() : '',
	};
}

async function getUidBySub(sub, issuer) {
	if (issuer) {
		const qualifiedUid = await getUidByIssuerSub(issuer, sub);
		if (qualifiedUid) {
			return qualifiedUid;
		}
		return await getLegacyUidBySubForIssuer(sub, issuer);
	}
	return await getLegacyUidBySub(sub);
}

async function getUidByIssuerSub(issuer, sub) {
	const field = issuerSubjectField(issuer, sub);
	const uid = await db.getObjectField(ISSUER_SUB_TO_UID_KEY, field);
	const objectUid = uid ? parseInt(uid, 10) : 0;
	const directUid = await db.getObjectField(issuerSubjectKey(issuer, sub), 'uid');
	const parsedDirectUid = directUid ? parseInt(directUid, 10) : 0;
	if (objectUid && parsedDirectUid && objectUid !== parsedDirectUid) {
		logger.warn('issuer subject mapping storage conflict', { objectUid, directUid: parsedDirectUid });
		throw fail('issuer-sub-mapping-storage-conflict', 'OIDC subject mapping storage is inconsistent');
	}
	return objectUid || parsedDirectUid || 0;
}

async function setIssuerSubMapping(issuer, sub, uid) {
	const field = issuerSubjectField(issuer, sub);
	await Promise.all([
		db.setObjectField(ISSUER_SUB_TO_UID_KEY, field, uid),
		db.setObjectField(issuerSubjectKey(issuer, sub), 'uid', uid),
	]);
}

async function getLegacyUidBySub(sub) {
	const uid = await db.getObjectField(SUB_TO_UID_KEY, sub);
	const objectUid = uid ? parseInt(uid, 10) : 0;
	const directUid = await db.getObjectField(subKey(sub), 'uid');
	const parsedDirectUid = directUid ? parseInt(directUid, 10) : 0;
	if (objectUid && parsedDirectUid && objectUid !== parsedDirectUid) {
		logger.warn('sub mapping storage conflict', { sub, objectUid, directUid: parsedDirectUid });
		throw fail('sub-mapping-storage-conflict', 'OIDC subject mapping storage is inconsistent');
	}
	return objectUid || parsedDirectUid || 0;
}

async function getLegacyUidBySubForIssuer(sub, issuer) {
	const legacyUid = await getLegacyUidBySub(sub);
	if (!legacyUid) {
		return 0;
	}
	const exists = await user.exists(legacyUid);
	if (!exists) {
		return legacyUid;
	}
	const storedIssuer = await user.getUserField(legacyUid, 'authentikIssuer');
	if (storedIssuer !== issuer) {
		logger.warn('legacy sub mapping issuer mismatch', { uid: legacyUid });
		return 0;
	}
	await setIssuerSubMapping(issuer, sub, legacyUid);
	return legacyUid;
}

async function deleteSubMapping(sub) {
	if (typeof db.deleteObjectField === 'function') {
		await db.deleteObjectField(SUB_TO_UID_KEY, sub);
		await db.deleteObjectField(subKey(sub), 'uid');
	} else if (typeof db.deleteObjectFields === 'function') {
		await db.deleteObjectFields(SUB_TO_UID_KEY, [sub]);
		await db.deleteObjectFields(subKey(sub), ['uid']);
	}
}

async function getUidBySid(sid) {
	if (!sid) {
		return null;
	}
	const uid = await db.getObjectField(SID_TO_UID_KEY, sid);
	if (!uid) {
		return null;
	}
	if (typeof uid === 'object') {
		return {
			uid: parseInt(uid.uid, 10) || 0,
			issuer: uid.issuer || '',
			sub: uid.sub || '',
			sessionId: uid.sessionId || '',
		};
	}
	return { uid: parseInt(uid, 10), issuer: '', sub: '', sessionId: '' };
}

async function deleteSidMapping(sid) {
	if (!sid) {
		return;
	}
	if (typeof db.deleteObjectField === 'function') {
		await db.deleteObjectField(SID_TO_UID_KEY, sid);
		return;
	}
	if (typeof db.deleteObjectFields === 'function') {
		await db.deleteObjectFields(SID_TO_UID_KEY, [sid]);
	}
}

async function updateSidSessionMapping(uid, sessionId) {
	const parsedUid = parseInt(uid, 10);
	if (!parsedUid || !sessionId) {
		return false;
	}
	const [sid, issuer, sub] = await Promise.all([
		user.getUserField(parsedUid, 'authentikLastSid'),
		user.getUserField(parsedUid, 'authentikIssuer'),
		user.getUserField(parsedUid, 'authentikSub'),
	]);
	if (!sid) {
		return false;
	}
	await db.setObjectField(SID_TO_UID_KEY, sid, {
		uid: parsedUid,
		issuer: issuer || '',
		sub: sub || '',
		sessionId,
	});
	return true;
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
		logger.warn('multiple users share verified email', { matchCount: uniqueMatches.length, uids: uniqueMatches });
		throw fail('email-maps-to-multiple-users', 'Verified email maps to multiple existing accounts');
	}
	return uniqueMatches[0] || 0;
}

async function withLinkLock(uid, fn) {
	const previous = linkTail.catch(() => {});
	let release;
	linkTail = new Promise((resolve) => {
		release = resolve;
	});
	await previous;
	let releaseDbLock = async () => {};
	try {
		releaseDbLock = await acquireDbLinkLock(uid);
		return await fn();
	} finally {
		try {
			await releaseDbLock();
		} finally {
			release();
		}
	}
}

async function linkSub(uid, claims, issuer) {
	return await withLinkLock(uid, () => linkSubUnlocked(uid, claims, issuer));
}

async function acquireDbLinkLock(uid) {
	if (typeof db.incrObjectField !== 'function') {
		return async () => {};
	}
	const field = String(parseInt(uid, 10));
	let count = await db.incrObjectField(LINK_LOCK_KEY, field);
	if (count > 1) {
		const startedAt = parseInt(await db.getObjectField(LINK_LOCK_AT_KEY, field), 10) || 0;
		if (!startedAt || Date.now() - startedAt <= LINK_LOCK_TTL_MS) {
			throw fail('concurrent-link', 'Concurrent OIDC subject linking is already in progress for this account');
		}
		await releaseDbLinkLock(field);
		count = await db.incrObjectField(LINK_LOCK_KEY, field);
		if (count > 1) {
			throw fail('concurrent-link', 'Concurrent OIDC subject linking is already in progress for this account');
		}
	}
	await db.setObjectField(LINK_LOCK_AT_KEY, field, Date.now());
	return async () => {
		await releaseDbLinkLock(field);
	};
}

async function releaseDbLinkLock(field) {
	if (typeof db.deleteObjectField === 'function') {
		await db.deleteObjectField(LINK_LOCK_KEY, field);
		await db.deleteObjectField(LINK_LOCK_AT_KEY, field);
	} else if (typeof db.deleteObjectFields === 'function') {
		await db.deleteObjectFields(LINK_LOCK_KEY, [field]);
		await db.deleteObjectFields(LINK_LOCK_AT_KEY, [field]);
	}
}

async function linkSubUnlocked(uid, claims, issuer) {
	const existingSub = await user.getUserField(uid, 'authentikSub');
	const existingIssuer = await user.getUserField(uid, 'authentikIssuer');
	if ((existingSub && existingSub !== claims.sub) || (existingIssuer && existingIssuer !== issuer)) {
		logger.warn('existing user has different linked sub', { uid, sub: claims.sub });
		throw fail('user-linked-to-different-sub', 'Existing account is linked to a different OIDC subject');
	}

	const currentUid = await getUidBySub(claims.sub, issuer);
	if (currentUid && currentUid !== parseInt(uid, 10)) {
		logger.warn('sub/email collision', { sub: claims.sub, subUid: currentUid, emailUid: uid });
		throw fail('sub-email-collision', 'OIDC subject is already linked to a different account');
	}

	const now = Date.now();
	const writes = [
		setIssuerSubMapping(issuer, claims.sub, uid),
		user.setUserFields(uid, {
			authentikSub: claims.sub,
			authentikIssuer: issuer,
			authentikLinkedAt: now,
			authentikLastLoginAt: now,
			authentikLastEmail: claims.email,
			authentikLastSid: claims.sid || '',
		}),
	];
	if (claims.sid) {
		writes.push(db.setObjectField(SID_TO_UID_KEY, claims.sid, {
			uid,
			issuer,
			sub: claims.sub,
			sessionId: claims.nodebbSessionId || '',
		}));
	}
	const legacyUid = await getLegacyUidBySub(claims.sub);
	if (!legacyUid) {
		writes.push(db.setObjectField(SUB_TO_UID_KEY, claims.sub, uid));
		writes.push(db.setObjectField(subKey(claims.sub), 'uid', uid));
	}
	await Promise.all(writes);
}

async function resolveExistingSub(uid, claims, issuer) {
	const exists = await user.exists(uid);
	if (!exists) {
		logger.warn('sub mapping points to missing user', { uid, sub: claims.sub });
		throw fail('sub-mapping-missing-user', 'OIDC subject mapping points to a missing account');
	}
	await assertUserCanLogin(uid);
	const emailUid = await getUidByEmail(claims.email);
	if (emailUid && parseInt(emailUid, 10) !== parseInt(uid, 10)) {
		logger.warn('sub/email collision', { sub: claims.sub, subUid: uid, emailUid });
		throw fail('sub-email-collision', 'OIDC subject and verified email map to different accounts');
	}
	await user.setUserFields(uid, {
		authentikIssuer: issuer,
		authentikLastLoginAt: Date.now(),
		authentikLastEmail: claims.email,
		authentikLastSid: claims.sid || '',
	});
	if (claims.sid) {
		await db.setObjectField(SID_TO_UID_KEY, claims.sid, {
			uid,
			issuer,
			sub: claims.sub,
			sessionId: claims.nodebbSessionId || '',
		});
	}
	logger.info('login by existing sub', { uid });
	return { uid };
}

async function assertUserCanLogin(uid) {
	if (user.bans && typeof user.bans.canLoginIfBanned === 'function') {
		const canLogin = await user.bans.canLoginIfBanned(uid);
		if (!canLogin) {
			throw fail('user-login-restricted', 'NodeBB account is restricted');
		}
	}
	const restrictedFields = [
		'suspended',
		'disabled',
		'deactivated',
		'deleted',
		'accountDisabled',
		'loginDisabled',
	];
	for (const field of restrictedFields) {
		const value = await user.getUserField(uid, field);
		if (value === true || value === 1 || value === '1' || value === 'true') {
			throw fail('user-login-restricted', 'NodeBB account is restricted');
		}
	}
}

async function assertTrustedEmailAutoLinkAllowed(uid) {
	await assertUserCanLogin(uid);
	const confirmed = await user.getUserField(uid, 'email:confirmed');
	if (!(confirmed === true || confirmed === 1 || confirmed === '1')) {
		throw fail('local-email-not-confirmed', 'Local email must already be confirmed before trusted OIDC email auto-linking');
	}
	if (await isPrivilegedUser(uid)) {
		throw fail('privileged-auto-link-blocked', 'Privileged accounts cannot be linked automatically by email');
	}
}

async function isPrivilegedUser(uid) {
	const fields = [
		'isAdmin',
		'administrator',
		'isAdministrator',
		'isGlobalModerator',
		'isModerator',
		'moderator',
	];
	for (const field of fields) {
		const value = await user.getUserField(uid, field);
		if (value === true || value === 1 || value === '1' || value === 'true') {
			return true;
		}
	}
	return false;
}

function isUsernameTakenError(err) {
	return err && /\[\[error:username-taken\]\]|username[ -]?taken/i.test(err.message || '');
}

async function createUser(claims, issuer, options = {}) {
	const usernameCollisionPolicy = options.usernameCollisionPolicy || 'unique';
	const baseUsername = username.baseUsername(claims);
	for (let attempt = 0; attempt < 20; attempt += 1) {
		const desiredUsername = attempt === 0 ? baseUsername : `${baseUsername}-${attempt.toString(36)}`;
		try {
			const uid = await user.create({
				username: desiredUsername,
				email: claims.email,
				fullname: claims.name || '',
			}, { emailVerification: 'verify' });
			await isolateNewUserProfile(uid);
			await linkSub(uid, claims, issuer);
			logger.info('created new user', { uid });
			return { uid };
		} catch (err) {
			if (!isUsernameTakenError(err)) {
				throw err;
			}
			if (usernameCollisionPolicy === 'reject') {
				throw fail('username-unavailable', 'OIDC preferred username is already unavailable');
			}
		}
	}
	throw fail('username-unavailable', 'Unable to create a unique username');
}

async function isolateNewUserProfile(uid) {
	const fields = NEW_USER_PROFILE_ISOLATION_FIELDS.reduce((memo, field) => {
		memo[field] = '';
		return memo;
	}, {});
	await user.setUserFields(uid, fields);
}

async function createUserFromEmail(claims, issuer, options = {}) {
	try {
		return await createUser(claims, issuer, options);
	} catch (err) {
		const emailUid = await getUidByEmail(claims.email);
		if (emailUid && options.accountLinkingPolicy === 'trusted_email_auto_link') {
			await assertTrustedEmailAutoLinkAllowed(emailUid);
			await linkSub(emailUid, claims, issuer);
			logger.info('linked existing user by verified email after create race', { uid: emailUid });
			return { uid: emailUid };
		}
		throw err;
	}
}

async function resolve(claims, options = {}) {
	const { issuer } = options;
	const normalized = validateClaims(claims);
	normalized.nodebbSessionId = options.nodebbSessionId || '';
	const subUid = await getUidBySub(normalized.sub, issuer);
	if (subUid) {
		const existingSubResult = await resolveExistingSub(subUid, normalized, issuer);
		if (existingSubResult) {
			return existingSubResult;
		}
	}

	if (!normalized.emailVerified) {
		logger.warn('unverified email', { sub: normalized.sub });
		throw fail('unverified-email', 'OIDC email must be verified');
	}

	const emailUid = await getUidByEmail(normalized.email);
	if (emailUid) {
		if (options.accountLinkingPolicy === 'trusted_email_auto_link') {
			await assertTrustedEmailAutoLinkAllowed(emailUid);
			await linkSub(emailUid, normalized, issuer);
			logger.info('linked existing user by verified email', { uid: emailUid });
			return { uid: emailUid };
		}
	}

	if (options.allowAccountCreation === false) {
		logger.warn('new sso account creation disabled', { sub: normalized.sub });
		throw fail('account-creation-disabled', 'SSO account creation is disabled');
	}

	return await createUserFromEmail(normalized, issuer, options);
}

module.exports = {
	SUB_TO_UID_KEY,
	ISSUER_SUB_TO_UID_KEY,
	SID_TO_UID_KEY,
	LINK_LOCK_KEY,
	LINK_LOCK_AT_KEY,
	LINK_LOCK_TTL_MS,
	subKey,
	issuerSubjectField,
	issuerSubjectKey,
	normalizeEmail,
	validateClaims,
	getUidBySub,
	getUidByIssuerSub,
	deleteSubMapping,
	getUidBySid,
	deleteSidMapping,
	updateSidSessionMapping,
	getUidByEmail,
	isUsernameTakenError,
	linkSub,
	isolateNewUserProfile,
	assertTrustedEmailAutoLinkAllowed,
	resolve,
};
