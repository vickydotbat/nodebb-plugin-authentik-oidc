'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

function loadDiscoveryWithOpenIdClient(openidClient) {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'openid-client') {
			return openidClient;
		}
		return originalLoad.call(this, request, parent, isMain);
	};
	delete require.cache[require.resolve('../lib/discovery')];
	const discovery = require('../lib/discovery');
	return {
		discovery,
		restore() {
			Module._load = originalLoad;
			delete require.cache[require.resolve('../lib/discovery')];
		},
	};
}

test('discovery preserves provider issuer exactly for token validation', async () => {
	const issuer = 'https://auth.example.com/application/o/nodebb/';
	let discoveryCall = null;
	const customFetch = Symbol('customFetch');
	const { discovery, restore } = loadDiscoveryWithOpenIdClient({
		customFetch,
		None() {
			return { method: 'none' };
		},
		async discovery(server, clientId, metadata, clientAuth, options) {
			discoveryCall = { server, clientId, metadata, clientAuth, options };
			return {
				serverMetadata() {
					return {
						issuer,
						authorization_endpoint: `${issuer}authorize/`,
						token_endpoint: `${issuer}token/`,
						userinfo_endpoint: `${issuer}userinfo/`,
						jwks_uri: `${issuer}jwks/`,
						end_session_endpoint: `${issuer}end-session/`,
					};
				},
			};
		},
	});
	try {
		const settings = await discovery.discover(issuer);
		assert.equal(discoveryCall.server.href, issuer);
		assert.equal(discoveryCall.clientAuth.method, 'none');
		assert.equal(typeof discoveryCall.options[customFetch], 'function');
		assert.equal(settings.issuer, issuer);
		assert.equal(settings.endSessionEndpoint, `${issuer}end-session/`);
	} finally {
		restore();
	}
});

test('issuer comparison requires exact issuer strings', () => {
	const discovery = require('../lib/discovery');
	assert.equal(discovery.issuersMatch(
		'https://auth.example.com/application/o/nodebb',
		'https://auth.example.com/application/o/nodebb/'
	), false);
	assert.equal(discovery.issuersMatch(
		'https://auth.example.com/application/o/nodebb',
		'https://auth.example.com/application/o/other/'
	), false);
	assert.equal(discovery.issuersMatch(
		'https://auth.example.com/application/o/nodebb/',
		'https://auth.example.com/application/o/nodebb/'
	), true);
});

test('discovery rejects unsafe provider endpoints before returning metadata', async () => {
	const issuer = 'https://auth.example.com/application/o/nodebb/';
	const { discovery, restore } = loadDiscoveryWithOpenIdClient({
		customFetch: Symbol('customFetch'),
		None() {
			return {};
		},
		async discovery() {
			return {
				serverMetadata() {
					return {
						issuer,
						authorization_endpoint: `${issuer}authorize/`,
						token_endpoint: 'http://auth.example.com/application/o/nodebb/token/',
						userinfo_endpoint: `${issuer}userinfo/`,
						jwks_uri: `${issuer}jwks/`,
					};
				},
			};
		},
	});
	try {
		await assert.rejects(
			discovery.discover(issuer),
			/Must be an HTTPS URL/
		);
	} finally {
		restore();
	}
});
