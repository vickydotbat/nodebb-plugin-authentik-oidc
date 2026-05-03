'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

function loadOidc() {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'jsonwebtoken') {
			return {};
		}
		return originalLoad.call(this, request, parent, isMain);
	};
	delete require.cache[require.resolve('../lib/oidc')];
	const oidc = require('../lib/oidc');
	return {
		oidc,
		restore() {
			Module._load = originalLoad;
			delete require.cache[require.resolve('../lib/oidc')];
		},
	};
}

function loadOidcWithJwks(keys) {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'jsonwebtoken') {
			return {};
		}
		if (request === './http' && parent && parent.filename.endsWith('/lib/oidc.js')) {
			return {
				async requestJson() {
					return { keys };
				},
			};
		}
		return originalLoad.call(this, request, parent, isMain);
	};
	delete require.cache[require.resolve('../lib/oidc')];
	const oidc = require('../lib/oidc');
	return {
		oidc,
		restore() {
			Module._load = originalLoad;
			delete require.cache[require.resolve('../lib/oidc')];
		},
	};
}

function settings(overrides = {}) {
	return {
		authorizationEndpoint: 'https://auth.example.com/application/o/nodebb/authorize/',
		clientId: 'nodebb',
		scopes: 'openid email profile',
		authorizationParameters: '',
		...overrides,
	};
}

test('authorization URL includes configured provider parameters', () => {
	const { oidc, restore } = loadOidc();
	try {
		const url = new URL(oidc.authorizationUrl(
			settings({ authorizationParameters: 'prompt=login&max_age=0' }),
			'https://forum.example.com/auth/authentik/callback',
			'state-1',
			{ nonce: 'nonce-1', codeChallenge: 'challenge-1' }
		));
		assert.equal(url.searchParams.get('prompt'), 'login');
		assert.equal(url.searchParams.get('max_age'), '0');
		assert.equal(url.searchParams.get('state'), 'state-1');
		assert.equal(url.searchParams.get('nonce'), 'nonce-1');
		assert.equal(url.searchParams.get('code_challenge'), 'challenge-1');
	} finally {
		restore();
	}
});

test('authorization URL rejects attempts to override plugin-controlled parameters', () => {
	const { oidc, restore } = loadOidc();
	try {
		assert.throws(
			() => oidc.authorizationUrl(
				settings({ authorizationParameters: 'state=attacker' }),
				'https://forum.example.com/auth/authentik/callback',
				'state-1',
				{ nonce: 'nonce-1' }
			),
			/state is controlled by the plugin/
		);
	} finally {
		restore();
	}
});

test('JWKS test reports sanitized supported signing key metadata', async () => {
	const { oidc, restore } = loadOidcWithJwks([
		{ kty: 'RSA', use: 'sig', kid: 'rsa-1', alg: 'RS256', n: 'redacted', e: 'AQAB' },
		{ kty: 'oct', use: 'enc', kid: 'enc-1' },
		{ kty: 'EC', kid: 'ec-1', crv: 'P-256', x: 'redacted', y: 'redacted' },
	]);
	try {
		const result = await oidc.testJwks('https://auth.example.com/jwks/');
		assert.equal(result.keyCount, 3);
		assert.equal(result.supportedSigningKeyCount, 2);
		assert.deepEqual(result.keyTypes, ['EC', 'RSA']);
		assert.deepEqual(result.algorithms, ['RS256']);
		assert.equal(result.hasKeyIds, true);
		assert.equal(JSON.stringify(result).includes('redacted'), false);
	} finally {
		restore();
	}
});

test('JWKS test fails when no supported signing keys are available', async () => {
	const { oidc, restore } = loadOidcWithJwks([
		{ kty: 'oct', use: 'enc', kid: 'enc-1' },
		{ kty: 'RSA', use: 'enc', kid: 'rsa-enc-1', alg: 'RS256' },
	]);
	try {
		await assert.rejects(
			oidc.testJwks('https://auth.example.com/jwks/'),
			/JWKS did not include supported signing keys/
		);
	} finally {
		restore();
	}
});
