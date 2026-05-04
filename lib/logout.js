'use strict';

const user = require.main.require('./src/user');

const config = require('./config');
const identity = require('./identity');
const logger = require('./logger');
const oidc = require('./oidc');

function getLogoutToken(req) {
	if (req.body && typeof req.body.logout_token === 'string') {
		return req.body.logout_token;
	}
	if (req.query && typeof req.query.logout_token === 'string') {
		return req.query.logout_token;
	}
	return '';
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
	if (!settings.backchannelLogoutEnabled) {
		logger.warn('back-channel logout ignored because it is disabled');
		return res.sendStatus(204);
	}

	try {
		const logoutToken = await oidc.verifyLogoutToken(settings, getLogoutToken(req));
		const result = await uidFromLogoutToken(logoutToken);
		if (!result.uid) {
			logger.warn('back-channel logout token did not match a linked NodeBB user', {
				hasSub: !!logoutToken.sub,
				hasSid: !!logoutToken.sid,
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
		return res.sendStatus(204);
	} catch (err) {
		const logContext = { code: err.code };
		if (err.level === 'warn') {
			logger.warn(err.message, logContext);
			return res.status(400).json({ message: err.message });
		}
		logger.error(err.stack || err.message);
		return res.status(400).json({ message: 'OIDC back-channel logout failed' });
	}
}

module.exports = {
	handleBackchannelLogout,
	uidFromLogoutToken,
};
