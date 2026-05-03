'use strict';

let winston;
try {
	winston = require.main.require('winston');
} catch (err) {
	winston = require('winston');
}

const PREFIX = '[plugin/authentik-oidc]';

function safeMeta(meta) {
	if (!meta) {
		return '';
	}
	const filtered = {};
	Object.keys(meta).forEach((key) => {
		if (/secret|token|code/i.test(key)) {
			return;
		}
		filtered[key] = meta[key];
	});
	return ` ${JSON.stringify(filtered)}`;
}

module.exports = {
	info(message, meta) {
		winston.info(`${PREFIX} ${message}${safeMeta(meta)}`);
	},
	warn(message, meta) {
		winston.warn(`${PREFIX} ${message}${safeMeta(meta)}`);
	},
	error(message, meta) {
		winston.error(`${PREFIX} ${message}${safeMeta(meta)}`);
	},
};
