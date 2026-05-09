'use strict';

let winston;
try {
	winston = require.main.require('winston');
} catch (err) {
	winston = require('winston');
}

const PREFIX = '[plugin/authentik-oidc]';
const { redact, redactString } = require('./redact');

function safeMeta(meta) {
	if (!meta) {
		return '';
	}
	return ` ${JSON.stringify(redact(meta))}`;
}

module.exports = {
	info(message, meta) {
		winston.info(`${PREFIX} ${redactString(message)}${safeMeta(meta)}`);
	},
	warn(message, meta) {
		winston.warn(`${PREFIX} ${redactString(message)}${safeMeta(meta)}`);
	},
	error(message, meta) {
		winston.error(`${PREFIX} ${redactString(message)}${safeMeta(meta)}`);
	},
};
