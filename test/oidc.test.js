'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const crypto = require('node:crypto');
const jose = require('jose');

function loadOidc() {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
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

function loadOidcWithOpenIdClient(openidClient) {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'openid-client') {
			return openidClient;
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

function loadOidcWithRealJwt({ jwksResponses, safeRequestUrl } = {}) {
	const originalLoad = Module._load;
	const responses = [...(jwksResponses || [])];
	Module._load = function (request, parent, isMain) {
		if (request === './http' && parent && parent.filename.endsWith('/lib/oidc.js')) {
			return {
				async requestJson() {
					return responses.shift() || jwksResponses[jwksResponses.length - 1];
				},
				async safeRequestUrl(url) {
					if (safeRequestUrl) {
						return await safeRequestUrl(url);
					}
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

function rsaKeyPair(kid = 'rsa-1') {
	const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const jwk = publicKey.export({ format: 'jwk' });
	jwk.kid = kid;
	jwk.use = 'sig';
	jwk.alg = 'RS256';
	return { privateKey, jwk, kid };
}

function signToken(privateKey, kid, claims, options = {}) {
	const alg = options.algorithm || 'RS256';
	return new jose.SignJWT(claims)
		.setProtectedHeader({ alg, kid })
		.sign(privateKey);
}

async function withJwksFetch(jwks, callback) {
	const originalFetch = global.fetch;
	global.fetch = async () => new Response(JSON.stringify(jwks), {
		status: 200,
		headers: { 'content-type': 'application/json' },
	});
	try {
		return await callback();
	} finally {
		global.fetch = originalFetch;
	}
}

function settings(overrides = {}) {
	return {
		authorizationEndpoint: 'https://auth.example.com/application/o/nodebb/authorize/',
		clientId: 'nodebb',
		scopes: 'openid email profile',
		authorizationParameters: '',
		forceProviderLogin: true,
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

test('authorization URL forces fresh provider login by default', () => {
	const { oidc, restore } = loadOidc();
	try {
		const url = new URL(oidc.authorizationUrl(
			settings({ forceProviderLogin: true }),
			'https://forum.example.com/auth/authentik/callback',
			'state-1',
			{ nonce: 'nonce-1' }
		));
		assert.equal(url.searchParams.get('prompt'), 'login');
		assert.equal(url.searchParams.get('max_age'), '0');
	} finally {
		restore();
	}
});

test('authorization URL can disable forced fresh provider login', () => {
	const { oidc, restore } = loadOidc();
	try {
		const url = new URL(oidc.authorizationUrl(
			settings({ forceProviderLogin: false }),
			'https://forum.example.com/auth/authentik/callback',
			'state-1',
			{ nonce: 'nonce-1' }
		));
		assert.equal(url.searchParams.has('prompt'), false);
		assert.equal(url.searchParams.has('max_age'), false);
	} finally {
		restore();
	}
});

test('provider logout URL returns to the plugin login route', () => {
	const { oidc, restore } = loadOidc();
	try {
		const url = new URL(oidc.providerLogoutUrl(
			{ endSessionEndpoint: 'https://auth.example.com/application/o/nodebb/end-session/' },
			'https://forum.example.com/auth/authentik'
		));
		assert.equal(url.href.startsWith('https://auth.example.com/application/o/nodebb/end-session/'), true);
		assert.equal(url.searchParams.get('post_logout_redirect_uri'), 'https://forum.example.com/auth/authentik');
	} finally {
		restore();
	}
});

test('provider logout URL can use an Authentik flow with next return parameter', () => {
	const { oidc, restore } = loadOidc();
	try {
		const url = new URL(oidc.providerLogoutUrl(
			{
				sessionClearEndpoint: 'https://auth.example.com/if/flow/default-invalidation-flow/',
				sessionClearReturnParameter: 'next',
			},
			'https://forum.example.com/auth/authentik'
		));
		assert.equal(url.href.startsWith('https://auth.example.com/if/flow/default-invalidation-flow/'), true);
		assert.equal(url.searchParams.get('next'), 'https://forum.example.com/auth/authentik');
	} finally {
		restore();
	}
});

test('provider relative URL keeps same-origin authorization returns inside Authentik', () => {
	const { oidc, restore } = loadOidc();
	try {
		assert.equal(
			oidc.providerRelativeUrl(
				'https://auth.example.com/application/o/authorize/?client_id=nodebb',
				'https://auth.example.com/if/flow/default-invalidation-flow/'
			),
			'/application/o/authorize/?client_id=nodebb'
		);
		assert.equal(
			oidc.providerRelativeUrl(
				'https://forum.example.com/auth/authentik',
				'https://auth.example.com/if/flow/default-invalidation-flow/'
			),
			'https://forum.example.com/auth/authentik'
		);
	} finally {
		restore();
	}
});

test('authorization URL does not override explicit provider prompt parameters', () => {
	const { oidc, restore } = loadOidc();
	try {
		const url = new URL(oidc.authorizationUrl(
			settings({
				forceProviderLogin: true,
				authorizationParameters: 'prompt=select_account&max_age=300',
			}),
			'https://forum.example.com/auth/authentik/callback',
			'state-1',
			{ nonce: 'nonce-1' }
		));
		assert.equal(url.searchParams.get('prompt'), 'select_account');
		assert.equal(url.searchParams.get('max_age'), '300');
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

test('safe fetch disables automatic redirects', async () => {
	const seen = [];
	const originalFetch = global.fetch;
	global.fetch = async (input, init) => {
		seen.push({ input, init });
		return new Response('{}', { status: 200 });
	};
	const { oidc, restore } = loadOidcWithRealJwt({
		jwksResponses: [{ keys: [] }],
		safeRequestUrl: async (url) => {
			seen.push({ safeUrl: url });
		},
	});
	try {
		await oidc.safeFetch('https://auth.example.com/token', { method: 'POST' });
		assert.equal(seen[0].safeUrl, 'https://auth.example.com/token');
		assert.equal(seen[1].init.redirect, 'manual');
	} finally {
		global.fetch = originalFetch;
		restore();
	}
});

test('safe fetch rejects redirect responses instead of following them', async () => {
	const originalFetch = global.fetch;
	global.fetch = async () => new Response('', {
		status: 302,
		headers: { location: 'http://127.0.0.1/internal' },
	});
	const { oidc, restore } = loadOidcWithRealJwt({
		jwksResponses: [{ keys: [] }],
	});
	try {
		await assert.rejects(
			oidc.safeFetch('https://auth.example.com/token', { method: 'POST' }),
			/redirect/
		);
	} finally {
		global.fetch = originalFetch;
		restore();
	}
});

test('authorization code grant asks openid-client to validate state, nonce, PKCE, ID token, and max age', async () => {
	let grantCall = null;
	const openidClient = {
		customFetch: Symbol('customFetch'),
		Configuration: class Configuration {
			constructor(server, clientId, metadata, auth) {
				this.server = server;
				this.clientId = clientId;
				this.metadata = metadata;
				this.auth = auth;
			}
		},
		ClientSecretBasic(secret) {
			return { method: 'basic', secret };
		},
		ClientSecretPost(secret) {
			return { method: 'post', secret };
		},
		None() {
			return { method: 'none' };
		},
		async authorizationCodeGrant(config, currentUrl, checks) {
			grantCall = { config, currentUrl, checks };
			return {
				access_token: 'access-token',
				id_token: 'id-token',
				claims() {
					return { sub: 'sub-1' };
				},
			};
		},
		buildAuthorizationUrl() {
			return new URL('https://auth.example.com/authorize');
		},
		async fetchUserInfo() {
			return {};
		},
	};
	const { oidc, restore } = loadOidcWithOpenIdClient(openidClient);
	try {
		await oidc.exchangeCode({
			issuer: 'https://auth.example.com/application/o/nodebb/',
			authorizationEndpoint: 'https://auth.example.com/authorize',
			tokenEndpoint: 'https://auth.example.com/token',
			userinfoEndpoint: 'https://auth.example.com/userinfo',
			jwksUri: 'https://auth.example.com/jwks',
			clientId: 'nodebb',
			clientSecret: 'secret',
			tokenEndpointAuthMethod: 'client_secret_basic',
			idTokenSigningAlg: 'RS256',
			forceProviderLogin: true,
		}, 'code-1', {
			state: 'state-1',
			nonce: 'nonce-1',
			codeVerifier: 'verifier-1',
		}, 'https://forum.example.com/auth/authentik/callback');

		assert.equal(grantCall.currentUrl.searchParams.get('code'), 'code-1');
		assert.equal(grantCall.currentUrl.searchParams.get('state'), 'state-1');
		assert.equal(grantCall.config.metadata.id_token_signed_response_alg, 'RS256');
		assert.deepEqual(grantCall.checks, {
			expectedState: 'state-1',
			expectedNonce: 'nonce-1',
			idTokenExpected: true,
			maxAge: 0,
			pkceCodeVerifier: 'verifier-1',
		});
	} finally {
		restore();
	}
});

test('processed token set claims are required for the openid-client login path', () => {
	const { oidc, restore } = loadOidc();
	try {
		assert.throws(
			() => oidc.claimsFromTokenSet({}, { access_token: 'access-token', id_token: 'id-token' }, { nonce: 'nonce-1' }),
			/validated ID token claims/
		);
	} finally {
		restore();
	}
});

test('processed token set claims still receive plugin freshness and nonce checks', () => {
	const { oidc, restore } = loadOidc();
	const now = Math.floor(Date.now() / 1000);
	try {
		assert.throws(
			() => oidc.claimsFromTokenSet({
				clientId: 'nodebb',
				forceProviderLogin: true,
			}, {
				claims() {
					return {
						sub: 'sub-1',
						exp: now + 300,
						iat: now,
						nonce: 'nonce-1',
					};
				},
			}, { nonce: 'nonce-1' }),
			/auth_time/
		);
		assert.throws(
			() => oidc.claimsFromTokenSet({
				clientId: 'nodebb',
				forceProviderLogin: false,
			}, {
				claims() {
					return {
						sub: 'sub-1',
						exp: now + 300,
						iat: now,
						nonce: 'other-nonce',
					};
				},
			}, { nonce: 'nonce-1' }),
			/nonce/
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

test('claim merging rejects conflicting email verification values', () => {
	const { oidc, restore } = loadOidc();
	try {
		assert.throws(
			() => oidc.mergeClaims(
				{ sub: 'sub-1', email: 'person@example.com', email_verified: false },
				{ sub: 'sub-1', email: 'person@example.com', email_verified: true }
			),
			/email verification/
		);
	} finally {
		restore();
	}
});

test('claim merging rejects conflicting email values', () => {
	const { oidc, restore } = loadOidc();
	try {
		assert.throws(
			() => oidc.mergeClaims(
				{ sub: 'sub-1', email: 'person@example.com', email_verified: true },
				{ sub: 'sub-1', email: 'other@example.com', email_verified: true }
			),
			/email claims do not match/
		);
	} finally {
		restore();
	}
});

test('claim merging keeps signed ID token profile fields over UserInfo conflicts', () => {
	const { oidc, restore } = loadOidc();
	try {
		const claims = oidc.mergeClaims(
			{
				sub: 'sub-1',
				email: 'person@example.com',
				email_verified: true,
				preferred_username: 'signed-name',
				name: 'Signed Name',
			},
			{
				sub: 'sub-1',
				email: 'person@example.com',
				email_verified: true,
				preferred_username: 'userinfo-name',
				name: 'UserInfo Name',
			}
		);
		assert.equal(claims.preferred_username, 'signed-name');
		assert.equal(claims.name, 'Signed Name');
	} finally {
		restore();
	}
});

test('normalized claims ignore groups and roles', () => {
	const { oidc, restore } = loadOidc();
	try {
		const claims = oidc.normalizeClaims({
			sub: 'sub-1',
			email: 'person@example.com',
			email_verified: true,
			groups: ['admin'],
			roles: ['moderator'],
		});
		assert.equal(Object.prototype.hasOwnProperty.call(claims, 'groups'), false);
		assert.equal(Object.prototype.hasOwnProperty.call(claims, 'roles'), false);
	} finally {
		restore();
	}
});

test('logout token verification accepts signed back-channel logout event', async () => {
	const { privateKey, jwk, kid } = rsaKeyPair('signing-key');
	const { oidc, restore } = loadOidcWithRealJwt({ jwksResponses: [{ keys: [jwk] }] });
	const token = await signToken(privateKey, kid, {
		iss: 'https://auth.example.com/application/o/nodebb/',
		aud: 'nodebb',
		sub: 'sub-1',
		sid: 'sid-1',
		iat: Math.floor(Date.now() / 1000),
		jti: 'logout-1',
		events: {
			'http://schemas.openid.net/event/backchannel-logout': {},
		},
	});
	try {
		const claims = await withJwksFetch({ keys: [jwk] }, () => oidc.verifyLogoutToken({
			jwksUri: 'https://auth.example.com/jwks/accept/',
			clientId: 'nodebb',
			issuer: 'https://auth.example.com/application/o/nodebb/',
		}, token));
		assert.equal(claims.sub, 'sub-1');
		assert.equal(claims.sid, 'sid-1');
		assert.equal(claims.jti, 'logout-1');
	} finally {
		restore();
	}
});

test('logout token verification rejects stale issued-at values', async () => {
	const { privateKey, jwk, kid } = rsaKeyPair('signing-key');
	const { oidc, restore } = loadOidcWithRealJwt({ jwksResponses: [{ keys: [jwk] }] });
	const token = await signToken(privateKey, kid, {
		iss: 'https://auth.example.com/application/o/nodebb/',
		aud: 'nodebb',
		sub: 'sub-1',
		iat: Math.floor((Date.now() - (11 * 60 * 1000)) / 1000),
		jti: 'logout-1',
		events: {
			'http://schemas.openid.net/event/backchannel-logout': {},
		},
	});
	try {
		await assert.rejects(
			withJwksFetch({ keys: [jwk] }, () => oidc.verifyLogoutToken({
				jwksUri: 'https://auth.example.com/jwks/stale/',
				clientId: 'nodebb',
				issuer: 'https://auth.example.com/application/o/nodebb/',
			}, token)),
			/issued-at is outside/
		);
	} finally {
		restore();
	}
});

test('logout token verification rejects missing logout event', async () => {
	const { privateKey, jwk, kid } = rsaKeyPair('signing-key');
	const { oidc, restore } = loadOidcWithRealJwt({ jwksResponses: [{ keys: [jwk] }] });
	const token = await signToken(privateKey, kid, {
		iss: 'https://auth.example.com/application/o/nodebb/',
		aud: 'nodebb',
		sub: 'sub-1',
		sid: 'sid-1',
		iat: Math.floor(Date.now() / 1000),
		jti: 'logout-1',
		events: {},
	});
	try {
		await assert.rejects(
			withJwksFetch({ keys: [jwk] }, () => oidc.verifyLogoutToken({
				jwksUri: 'https://auth.example.com/jwks/missing-event/',
				clientId: 'nodebb',
				issuer: 'https://auth.example.com/application/o/nodebb/',
			}, token)),
			/missing the back-channel logout event/
		);
	} finally {
		restore();
	}
});

test('logout token verification rejects nonce', async () => {
	const { privateKey, jwk, kid } = rsaKeyPair('signing-key');
	const { oidc, restore } = loadOidcWithRealJwt({ jwksResponses: [{ keys: [jwk] }] });
	const token = await signToken(privateKey, kid, {
		iss: 'https://auth.example.com/application/o/nodebb/',
		aud: 'nodebb',
		sub: 'sub-1',
		iat: Math.floor(Date.now() / 1000),
		jti: 'logout-1',
		nonce: 'not-allowed',
		events: {
			'http://schemas.openid.net/event/backchannel-logout': {},
		},
	});
	try {
		await assert.rejects(
			withJwksFetch({ keys: [jwk] }, () => oidc.verifyLogoutToken({
				jwksUri: 'https://auth.example.com/jwks/nonce/',
				clientId: 'nodebb',
				issuer: 'https://auth.example.com/application/o/nodebb/',
			}, token)),
			/must not contain nonce/
		);
	} finally {
		restore();
	}
});

test('real logout token verification rejects unsigned, wrong issuer, wrong audience, and unknown kid tokens', async () => {
	const now = Math.floor(Date.now() / 1000);
	const { privateKey, jwk, kid } = rsaKeyPair('logout-rsa-1');
	const { oidc, restore } = loadOidcWithRealJwt({
		jwksResponses: [{ keys: [jwk] }, { keys: [jwk] }, { keys: [jwk] }, { keys: [jwk] }],
	});
	const baseSettings = {
		jwksUri: 'https://auth.example.com/jwks/logout/',
		clientId: 'nodebb',
		issuer: 'https://auth.example.com/application/o/nodebb/',
		idTokenSigningAlg: 'RS256',
	};
	const baseClaims = {
		iss: baseSettings.issuer,
		aud: 'nodebb',
		sub: 'sub-1',
		iat: now,
		jti: 'logout-1',
		events: {
			'http://schemas.openid.net/event/backchannel-logout': {},
		},
	};
	try {
		const unsigned = [
			Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url'),
			Buffer.from(JSON.stringify(baseClaims)).toString('base64url'),
			'',
		].join('.');
			await assert.rejects(
				oidc.verifyLogoutToken(baseSettings, unsigned),
				/Algorithm.*not allowed/
			);
			await assert.rejects(
				withJwksFetch({ keys: [jwk] }, async () => oidc.verifyLogoutToken(baseSettings, await signToken(privateKey, kid, { ...baseClaims, iss: 'https://evil.example.com/' }))),
				/iss|issuer/
			);
			await assert.rejects(
				withJwksFetch({ keys: [jwk] }, async () => oidc.verifyLogoutToken(baseSettings, await signToken(privateKey, kid, { ...baseClaims, aud: 'other-client' }))),
				/aud|audience/
			);
			await assert.rejects(
				withJwksFetch({ keys: [jwk] }, async () => oidc.verifyLogoutToken(baseSettings, await signToken(privateKey, 'unknown-kid', baseClaims))),
				/applicable key|signing key/
			);
	} finally {
		restore();
	}
});
