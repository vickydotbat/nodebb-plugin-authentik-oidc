'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createMocks, installNodebbMocks } = require('./bootstrap');

function loadDiagnostics(mocks) {
	const restore = installNodebbMocks(mocks);
	delete require.cache[require.resolve('../lib/diagnostics')];
	const diagnostics = require('../lib/diagnostics');
	return { diagnostics, restore };
}

test('last failure diagnostics store only sanitized claim metadata', async () => {
	const mocks = createMocks();
	const { diagnostics, restore } = loadDiagnostics(mocks);
	try {
		await diagnostics.recordFailure({
			err: Object.assign(new Error('OIDC email must be verified'), {
				code: 'unverified-email',
				level: 'warn',
			}),
			stage: 'callback',
			settings: { issuer: 'https://auth.example.com/application/o/nodebb/' },
			idClaims: {
				sub: 'sub-1',
				email: 'person@example.com',
				email_verified: false,
				access_token: 'must-not-store',
			},
			userinfoClaims: null,
			mergedClaims: {
				sub: 'sub-1',
				email: 'person@example.com',
				email_verified: false,
			},
		});
		const failure = await diagnostics.getLastFailure();
		assert.equal(failure.code, 'unverified-email');
		assert.equal(failure.idTokenClaims.hasSub, true);
		assert.equal(failure.idTokenClaims.emailVerifiedType, 'boolean');
		assert.equal(failure.idTokenClaims.emailVerifiedValue, false);
		assert.equal(JSON.stringify(failure).includes('must-not-store'), false);
		assert.equal(JSON.stringify(failure).includes('person@example.com'), false);
	} finally {
		restore();
	}
});
