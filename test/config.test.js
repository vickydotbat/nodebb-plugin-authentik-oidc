'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createMocks, installNodebbMocks } = require('./bootstrap');

function loadConfig(mocks) {
	const restore = installNodebbMocks(mocks);
	delete require.cache[require.resolve('../lib/config')];
	const config = require('../lib/config');
	return { config, restore };
}

function enabledSettings(overrides = {}) {
	return {
		enabled: true,
		clientId: 'nodebb',
		clientSecret: 'secret',
		issuer: 'https://auth.example.com/application/o/nodebb/',
		authorizationEndpoint: 'https://auth.example.com/application/o/nodebb/authorize/',
		tokenEndpoint: 'https://auth.example.com/application/o/nodebb/token/',
		userinfoEndpoint: 'https://auth.example.com/application/o/nodebb/userinfo/',
		jwksUri: 'https://auth.example.com/application/o/nodebb/jwks/',
		scopes: 'openid email profile',
		...overrides,
	};
}

test('self-service URLs normalize and validate as optional HTTPS settings', async () => {
	const mocks = createMocks();
	const { config, restore } = loadConfig(mocks);
	try {
		const saved = await config.saveSettings(enabledSettings({
			selfServiceProfileUrl: ' https://auth.example.com/if/user/#/settings ',
			selfServicePasswordUrl: '',
			selfServiceMfaUrl: 'https://auth.example.com/if/user/#/settings;page=mfa',
			selfServiceSessionsUrl: 'https://auth.example.com/if/user/#/sessions',
		}));
		assert.equal(saved.selfServiceProfileUrl, 'https://auth.example.com/if/user/#/settings');
		assert.equal(saved.selfServicePasswordUrl, '');
		assert.equal(saved.selfServiceMfaUrl, 'https://auth.example.com/if/user/#/settings;page=mfa');
		assert.equal(saved.selfServiceSessionsUrl, 'https://auth.example.com/if/user/#/sessions');
	} finally {
		restore();
	}
});

test('invalid self-service URLs produce field-level validation errors', async () => {
	const mocks = createMocks();
	const { config, restore } = loadConfig(mocks);
	try {
		await assert.rejects(
			config.saveSettings(enabledSettings({
				selfServiceProfileUrl: 'http://auth.example.com/if/user/',
			})),
			(err) => {
				assert.equal(err.errors.selfServiceProfileUrl, 'Must be an HTTPS URL');
				return true;
			}
		);
	} finally {
		restore();
	}
});

test('self-service URLs are validated even when login is disabled', async () => {
	const mocks = createMocks();
	const { config, restore } = loadConfig(mocks);
	try {
		await assert.rejects(
			config.saveSettings({
				enabled: false,
				selfServiceProfileUrl: 'javascript:alert(1)',
			}),
			(err) => {
				assert.equal(err.errors.selfServiceProfileUrl, 'Must be an HTTPS URL');
				return true;
			}
		);
	} finally {
		restore();
	}
});

test('provider URLs reject private network targets by default', () => {
	const mocks = createMocks();
	const { config, restore } = loadConfig(mocks);
	try {
		assert.throws(
			() => config.assertSafeUrl('https://127.0.0.1:9443/application/o/nodebb/', 'issuer'),
			/Must not target localhost or private network addresses/
		);
		assert.throws(
			() => config.assertSafeUrl('https://192.168.1.20/application/o/nodebb/', 'issuer'),
			/Must not target localhost or private network addresses/
		);
	} finally {
		restore();
	}
});
