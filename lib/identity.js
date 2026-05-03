'use strict';

const db = require.main.require('./src/database');
const user = require.main.require('./src/user');
const logger = require('./logger');
const { fail } = require('./errors');
const username = require('./username');

const SUB_TO_UID_KEY = 'authentik:sub:uid';

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
		throw fail('sub-mapped-user-missing', 'OIDC subject maps to a missing NodeBB account');
	}
	const emailUid = await user.getUidByEmail(claims.email);
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

async function createUser(claims, issuer) {
	const desiredUsername = await username.uniqueUsername(claims, user);
	const uid = await user.create({
		username: desiredUsername,
		email: claims.email,
		fullname: claims.name || '',
	}, { emailVerification: 'verify' });
	await linkSub(uid, claims, issuer);
	logger.info('created new user', { uid });
	return { uid };
}

async function resolve(claims, { issuer } = {}) {
	const normalized = validateClaims(claims);
	const subUid = await getUidBySub(normalized.sub);
	if (subUid) {
		return await resolveExistingSub(subUid, normalized, issuer);
	}

	const emailUid = await user.getUidByEmail(normalized.email);
	if (emailUid) {
		await linkSub(emailUid, normalized, issuer);
		logger.info('linked existing user by verified email', { uid: emailUid });
		return { uid: emailUid };
	}

	return await createUser(normalized, issuer);
}

module.exports = {
	SUB_TO_UID_KEY,
	normalizeEmail,
	validateClaims,
	getUidBySub,
	linkSub,
	resolve,
};
