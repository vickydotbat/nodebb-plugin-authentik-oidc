'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

function loadDiscoveryWithMetadata(metadata) {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === './http' && parent && parent.filename.endsWith('/lib/discovery.js')) {
			return {
				async requestJson() {
					return metadata;
				},
			};
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
	const { discovery, restore } = loadDiscoveryWithMetadata({
		issuer,
		authorization_endpoint: `${issuer}authorize/`,
		token_endpoint: `${issuer}token/`,
		userinfo_endpoint: `${issuer}userinfo/`,
		jwks_uri: `${issuer}jwks/`,
	});
	try {
		const settings = await discovery.discover('https://auth.example.com/application/o/nodebb');
		assert.equal(settings.issuer, issuer);
	} finally {
		restore();
	}
});

test('issuer comparison accepts only trailing slash differences', () => {
	const discovery = require('../lib/discovery');
	assert.equal(discovery.issuersMatch(
		'https://auth.example.com/application/o/nodebb',
		'https://auth.example.com/application/o/nodebb/'
	), true);
	assert.equal(discovery.issuersMatch(
		'https://auth.example.com/application/o/nodebb',
		'https://auth.example.com/application/o/other/'
	), false);
});
