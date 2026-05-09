'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

function loadLogger() {
	const logs = [];
	const sink = {
		info(message) {
			logs.push({ level: 'info', message });
		},
		warn(message) {
			logs.push({ level: 'warn', message });
		},
		error(message) {
			logs.push({ level: 'error', message });
		},
	};
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'winston') {
			return sink;
		}
		return originalLoad.call(this, request, parent, isMain);
	};
	delete require.cache[require.resolve('../lib/logger')];
	const logger = require('../lib/logger');
	return {
		logger,
		logs,
		restore() {
			Module._load = originalLoad;
			delete require.cache[require.resolve('../lib/logger')];
		},
	};
}

test('logger recursively redacts secret-bearing metadata values', () => {
	const { logger, logs, restore } = loadLogger();
	try {
		logger.warn('test Authorization: Bearer abc.def.ghi', {
			message: 'client_secret=s3 code=c0 access_token=secret-access id_token=secret-id',
			nested: {
				headers: {
					cookie: 'sid=secret-cookie',
					authorization: 'Bearer nested.jwt.token',
				},
				url: 'https://auth.example.com/token?code=secret-code&client_secret=secret-client-secret',
			},
		});
		const output = logs[0].message;
		[
			'abc.def.ghi',
			's3',
			'c0',
			'secret-access',
			'secret-id',
			'secret-cookie',
			'nested.jwt.token',
			'secret-code',
			'secret-client-secret',
		].forEach((secret) => {
			assert.equal(output.includes(secret), false, `${secret} leaked in ${output}`);
		});
		assert.equal(output.includes('[redacted]'), true);
	} finally {
		restore();
	}
});

test('redaction covers callback URLs, nested arrays, token responses, and Authentik JSON errors', () => {
	const { logger, logs, restore } = loadLogger();
	try {
		logger.error('callback failed https://forum.example.com/auth/authentik/callback?code=secret-code&state=secret-state', {
			details: [
				{
					response: {
						error_description: JSON.stringify({
							error: 'invalid_grant',
							access_token: 'secret-access',
							refresh_token: 'secret-refresh',
							id_token: 'header.payload.signature',
						}),
					},
				},
				'https://auth.example.com/token?logout_token=secret-logout&nonce=secret-nonce',
			],
		});
		const output = logs[0].message;
		[
			'secret-code',
			'secret-state',
			'secret-access',
			'secret-refresh',
			'header.payload.signature',
			'secret-logout',
			'secret-nonce',
		].forEach((secret) => {
			assert.equal(output.includes(secret), false, `${secret} leaked in ${output}`);
		});
	} finally {
		restore();
	}
});
