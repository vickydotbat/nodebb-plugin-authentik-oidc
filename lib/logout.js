'use strict';

const db = require.main.require('./src/database');
const user = require.main.require('./src/user');

const config = require('./config');
const diagnostics = require('./diagnostics');
const identity = require('./identity');
const logger = require('./logger');
const oidc = require('./oidc');
const { fail } = require('./errors');

const MAX_LOGOUT_BODY_BYTES = 1024 * 1024;
const USED_LOGOUT_JTI_KEY = 'authentik:logout:jti';
const USED_LOGOUT_JTI_AT_KEY = 'authentik:logout:jti:at';
const LOGOUT_JTI_RETENTION_MS = 24 * 60 * 60 * 1000;

async function readRawBody(req) {
	if (!req || req.readableEnded || req.complete) {
		return '';
	}
	return await new Promise((resolve, reject) => {
		let size = 0;
		const chunks = [];
		req.on('data', (chunk) => {
			size += chunk.length;
			if (size > MAX_LOGOUT_BODY_BYTES) {
				reject(new Error('OIDC logout request body is too large'));
				req.destroy();
				return;
			}
			chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
		});
		req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
		req.on('error', reject);
	});
}

function parseLogoutTokenFromText(text, contentType) {
	if (!text) {
		return '';
	}
	const type = String(contentType || '').toLowerCase();
	if (type.includes('application/json')) {
		try {
			const parsed = JSON.parse(text);
			return parsed && typeof parsed.logout_token === 'string' ? parsed.logout_token : '';
		} catch (err) {
			return '';
		}
	}
	if (type.includes('application/x-www-form-urlencoded') || text.includes('logout_token=')) {
		return new URLSearchParams(text).get('logout_token') || '';
	}
	return text.trim();
}

async function getLogoutToken(req) {
	if (req.body && typeof req.body.logout_token === 'string') {
		return req.body.logout_token;
	}
	if (req.query && typeof req.query.logout_token === 'string') {
		throw fail('logout-token-in-query', 'OIDC logout token must be sent in the request body', 'warn');
	}
	return parseLogoutTokenFromText(
		await readRawBody(req),
		req.headers && req.headers['content-type']
	);
}

async function rejectReplay(logoutToken) {
	const jti = logoutToken && logoutToken.jti ? String(logoutToken.jti) : '';
	if (!jti) {
		return;
	}
	await pruneUsedLogoutJtis();
	const count = await db.incrObjectField(USED_LOGOUT_JTI_KEY, jti);
	if (count > 1) {
		throw fail('logout-token-replay', 'OIDC logout token has already been used', 'warn');
	}
	await db.setObjectField(USED_LOGOUT_JTI_AT_KEY, jti, Date.now());
}

async function pruneUsedLogoutJtis(now = Date.now()) {
	if (typeof db.getObject !== 'function') {
		return;
	}
	const [rawCache, rawTimestamps] = await Promise.all([
		db.getObject(USED_LOGOUT_JTI_KEY),
		db.getObject(USED_LOGOUT_JTI_AT_KEY),
	]);
	const cache = rawCache || {};
	const timestamps = rawTimestamps || {};
	const expired = [
		...new Set([
			...Object.keys(cache),
			...Object.keys(timestamps),
		]),
	].filter(jti => !cache[jti] || isExpiredReplayTimestamp(timestamps[jti], now));
	if (!expired.length) {
		return;
	}
	if (typeof db.deleteObjectFields === 'function') {
		await Promise.all([
			db.deleteObjectFields(USED_LOGOUT_JTI_KEY, expired),
			db.deleteObjectFields(USED_LOGOUT_JTI_AT_KEY, expired),
		]);
		return;
	}
	await Promise.all(expired.flatMap(jti => [
		db.deleteObjectField(USED_LOGOUT_JTI_KEY, jti),
		db.deleteObjectField(USED_LOGOUT_JTI_AT_KEY, jti),
	]));
}

function isExpiredReplayTimestamp(value, now = Date.now()) {
	const timestamp = parseInt(value, 10);
	if (!Number.isFinite(timestamp) || timestamp <= 0) {
		return true;
	}
	const timestampMs = timestamp < 1000000000000 ? timestamp * 1000 : timestamp;
	return now - timestampMs > LOGOUT_JTI_RETENTION_MS;
}

async function uidFromLogoutToken(logoutToken) {
	if (logoutToken.sub) {
		const uid = await identity.getUidBySub(logoutToken.sub, logoutToken.issuer);
		if (uid) {
			return { uid, source: 'sub', sessionId: '' };
		}
	}
	if (logoutToken.sid) {
		const sidMapping = await identity.getUidBySid(logoutToken.sid);
		if (sidMapping && sidMapping.uid) {
			if (logoutToken.issuer && sidMapping.issuer && sidMapping.issuer !== logoutToken.issuer) {
				return { uid: 0, source: '' };
			}
			return { uid: sidMapping.uid, source: 'sid', sessionId: sidMapping.sessionId || '' };
		}
	}
	return { uid: 0, source: '', sessionId: '' };
}

async function getTrackedSessionCount(uid) {
	if (!uid || !user.auth || typeof user.auth.getSessions !== 'function') {
		return -1;
	}
	try {
		const sessions = await user.auth.getSessions(uid);
		return Array.isArray(sessions) ? sessions.length : -1;
	} catch (err) {
		logger.warn('failed to inspect NodeBB sessions during OIDC logout', {
			uid,
			message: err.message,
		});
		return -1;
	}
}

async function handleBackchannelLogout(req, res) {
	const settings = await config.getSettings();
	let logoutTokenValue = '';
	if (!settings.backchannelLogoutEnabled) {
		logger.warn('back-channel logout ignored because it is disabled');
		await diagnostics.recordLogoutEvent({
			enabled: false,
			outcome: 'ignored-disabled',
			statusCode: 204,
		});
		return res.sendStatus(204);
	}

	try {
		logoutTokenValue = await getLogoutToken(req);
		const logoutToken = await oidc.verifyLogoutToken(settings, logoutTokenValue);
		await rejectReplay(logoutToken);
		const result = await uidFromLogoutToken(logoutToken);
		if (!result.uid) {
			logger.warn('back-channel logout token did not match a linked NodeBB user', {
				hasSub: !!logoutToken.sub,
				hasSid: !!logoutToken.sid,
			});
			await diagnostics.recordLogoutEvent({
				enabled: true,
				outcome: 'unmatched',
				hasLogoutToken: !!logoutTokenValue,
				tokenValidated: true,
				hasSub: !!logoutToken.sub,
				hasSid: !!logoutToken.sid,
				statusCode: 204,
			});
			return res.sendStatus(204);
		}

		const sessionsBefore = await getTrackedSessionCount(result.uid);
		if (result.source === 'sid' && result.sessionId && user.auth && typeof user.auth.revokeSession === 'function') {
			await user.auth.revokeSession(result.sessionId, result.uid);
		} else {
			await user.auth.revokeAllSessions(result.uid);
		}
		const sessionsAfter = await getTrackedSessionCount(result.uid);
		if (logoutToken.sid) {
			await identity.deleteSidMapping(logoutToken.sid);
		}
		logger.info('revoked NodeBB sessions from OIDC back-channel logout', {
			uid: result.uid,
			source: result.source,
		});
		await diagnostics.recordLogoutEvent({
			enabled: true,
			outcome: 'revoked',
			hasLogoutToken: !!logoutTokenValue,
			tokenValidated: true,
			hasSub: !!logoutToken.sub,
			hasSid: !!logoutToken.sid,
			uid: result.uid,
			source: result.source,
			sessionsBefore,
			sessionsAfter,
			statusCode: 204,
		});
		return res.sendStatus(204);
	} catch (err) {
		const logContext = { code: err.code };
		if (err.level === 'warn') {
			logger.warn(err.message, logContext);
			await diagnostics.recordLogoutEvent({
				enabled: true,
				outcome: 'rejected',
				hasLogoutToken: !!logoutTokenValue,
				code: err.code,
				message: err.message,
				statusCode: 400,
			});
			return res.status(400).json({ message: err.message });
		}
		logger.error(err.stack || err.message);
		await diagnostics.recordLogoutEvent({
			enabled: true,
			outcome: 'error',
			hasLogoutToken: !!logoutTokenValue,
			code: err.code,
			message: err.message,
			statusCode: 400,
		});
		return res.status(400).json({ message: 'OIDC back-channel logout failed' });
	}
}

module.exports = {
	LOGOUT_JTI_RETENTION_MS,
	USED_LOGOUT_JTI_AT_KEY,
	USED_LOGOUT_JTI_KEY,
	getLogoutToken,
	handleBackchannelLogout,
	isExpiredReplayTimestamp,
	parseLogoutTokenFromText,
	pruneUsedLogoutJtis,
	rejectReplay,
	uidFromLogoutToken,
	getTrackedSessionCount,
};
