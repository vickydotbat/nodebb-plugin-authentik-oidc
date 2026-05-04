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

test('last authorization diagnostics preserve sanitized provider-relative clear-session return target', async () => {
	const mocks = createMocks();
	const { diagnostics, restore } = loadDiagnostics(mocks);
	try {
		await diagnostics.recordAuthorizationStart({
			stage: 'provider-session-clear',
			clearProviderSessionBeforeLogin: true,
			forceProviderLogin: true,
			hasEndSessionEndpoint: true,
			sessionClearEndpointOverride: true,
			sessionClearReturnParameter: 'next',
			authorizationParameters: '',
			redirectTarget: 'https://auth.example.com/if/flow/default-invalidation-flow/?next=%2Fapplication%2Fo%2Fauthorize%2F%3Fresponse_type%3Dcode%26client_id%3Dnodebb%26redirect_uri%3Dhttps%253A%252F%252Fforum.example.com%252Fauth%252Fauthentik%252Fcallback%26scope%3Dopenid%2Bemail%2Bprofile%26state%3Dsecret-state%26nonce%3Dsecret-nonce%26prompt%3Dlogin%26max_age%3D0',
			returnTo: '/application/o/authorize/?response_type=code&client_id=nodebb&redirect_uri=https%3A%2F%2Fforum.example.com%2Fauth%2Fauthentik%2Fcallback&scope=openid+email+profile&state=secret-state&nonce=secret-nonce&prompt=login&max_age=0',
			returnToWasProviderRelative: true,
		});
		const authorization = await diagnostics.getLastAuthorizationStart();
		assert.equal(authorization.stage, 'provider-session-clear');
		assert.equal(authorization.sessionClearEndpointOverride, true);
		assert.equal(authorization.sessionClearReturnParameter, 'next');
		assert.equal(authorization.returnToWasProviderRelative, true);
		assert.equal(authorization.returnTo.startsWith('/application/o/authorize/'), true);
		assert.equal(authorization.returnTo.includes('prompt=login'), true);
		assert.equal(authorization.returnTo.includes('max_age=0'), true);
		assert.equal(authorization.returnTo.includes('secret-state'), false);
		assert.equal(authorization.returnTo.includes('secret-nonce'), false);
	} finally {
		restore();
	}
});
