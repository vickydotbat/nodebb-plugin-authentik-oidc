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

test('last authorization diagnostics sanitize outbound redirect URLs', async () => {
	const mocks = createMocks();
	const { diagnostics, restore } = loadDiagnostics(mocks);
	try {
		await diagnostics.recordAuthorizationStart({
			stage: 'authorization',
			clearProviderSessionBeforeLogin: true,
			forceProviderLogin: true,
			hasEndSessionEndpoint: true,
			authorizationParameters: 'prompt=login',
			redirectTarget: 'https://auth.example.com/application/o/authorize/?response_type=code&client_id=nodebb&redirect_uri=https%3A%2F%2Fforum.example.com%2Fauth%2Fauthentik%2Fcallback&scope=openid+email+profile&state=secret-state&nonce=secret-nonce&code_challenge=secret-challenge&code_challenge_method=S256&prompt=login&max_age=0',
			returnTo: 'https://forum.example.com/auth/authentik?authentikFreshLogin=1',
		});
		const authorization = await diagnostics.getLastAuthorizationStart();
		assert.equal(authorization.stage, 'authorization');
		assert.equal(authorization.clearProviderSessionBeforeLogin, true);
		assert.equal(authorization.forceProviderLogin, true);
		assert.equal(authorization.hasEndSessionEndpoint, true);
		assert.equal(authorization.redirectTarget.includes('prompt=login'), true);
		assert.equal(authorization.redirectTarget.includes('max_age=0'), true);
		assert.equal(authorization.redirectTarget.includes('secret-state'), false);
		assert.equal(authorization.redirectTarget.includes('secret-nonce'), false);
		assert.equal(authorization.redirectTarget.includes('secret-challenge'), false);
	} finally {
		restore();
	}
});
