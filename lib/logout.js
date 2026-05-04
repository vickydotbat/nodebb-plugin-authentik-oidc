'use strict';

const user = require.main.require('./src/user');

const config = require('./config');
const diagnostics = require('./diagnostics');
const identity = require('./identity');
const logger = require('./logger');
const oidc = require('./oidc');

const MAX_LOGOUT_BODY_BYTES = 1024 * 1024;

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
		return req.query.logout_token;
	}
	return parseLogoutTokenFromText(
		await readRawBody(req),
		req.headers && req.headers['content-type']
	);
}

async function uidFromLogoutToken(logoutToken) {
	if (logoutToken.sub) {
		const uid = await identity.getUidBySub(logoutToken.sub);
		if (uid) {
			return { uid, source: 'sub' };
		}
	}
	if (logoutToken.sid) {
		const uid = await identity.getUidBySid(logoutToken.sid);
		if (uid) {
			return { uid, source: 'sid' };
		}
	}
	return { uid: 0, source: '' };
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

		await user.auth.revokeAllSessions(result.uid);
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
	getLogoutToken,
	handleBackchannelLogout,
	parseLogoutTokenFromText,
	uidFromLogoutToken,
};
