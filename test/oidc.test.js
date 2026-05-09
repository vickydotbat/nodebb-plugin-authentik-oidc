'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const crypto = require('node:crypto');

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

function loadOidcForIdToken({ header, keys, claims }) {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'jsonwebtoken') {
			return {
				decode() {
					return { header };
				},
				verify() {
					return claims || { sub: 'sub-1', nonce: 'nonce-1' };
				},
			};
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

function loadOidcForLogoutToken({ header, keys, claims }) {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'jsonwebtoken') {
			return {
				decode() {
					return { header };
				},
				verify() {
					return claims;
				},
			};
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
			'https://forum.example.com/auth/authentik?authentikFreshLogin=1'
		));
		assert.equal(url.href.startsWith('https://auth.example.com/application/o/nodebb/end-session/'), true);
		assert.equal(url.searchParams.get('post_logout_redirect_uri'), 'https://forum.example.com/auth/authentik?authentikFreshLogin=1');
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
			'https://forum.example.com/auth/authentik?authentikFreshLogin=1'
		));
		assert.equal(url.href.startsWith('https://auth.example.com/if/flow/default-invalidation-flow/'), true);
		assert.equal(url.searchParams.get('next'), 'https://forum.example.com/auth/authentik?authentikFreshLogin=1');
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
				'https://forum.example.com/auth/authentik?authentikFreshLogin=1',
				'https://auth.example.com/if/flow/default-invalidation-flow/'
			),
			'https://forum.example.com/auth/authentik?authentikFreshLogin=1'
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

test('ID token verification rejects unsupported algorithms before key selection', async () => {
	const { oidc, restore } = loadOidcForIdToken({
		header: { alg: 'HS256', kid: 'shared-secret' },
		keys: [{ kty: 'oct', kid: 'shared-secret' }],
	});
	try {
		await assert.rejects(
			oidc.verifyIdToken({
				jwksUri: 'https://auth.example.com/jwks/',
				clientId: 'nodebb',
				issuer: 'https://auth.example.com/application/o/nodebb/',
			}, 'token', 'nonce-1'),
			/unsupported signing algorithm/
		);
	} finally {
		restore();
	}
});

test('ID token verification ignores non-signing keys with matching kid', async () => {
	const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const signingJwk = publicKey.export({ format: 'jwk' });
	signingJwk.kid = 'signing-key';
	signingJwk.use = 'sig';
	signingJwk.alg = 'RS256';

	const { oidc, restore } = loadOidcForIdToken({
		header: { alg: 'RS256', kid: 'enc-key' },
		keys: [
			{ ...signingJwk, kid: 'enc-key', use: 'enc' },
			signingJwk,
		],
	});
	try {
		await assert.rejects(
			oidc.verifyIdToken({
				jwksUri: 'https://auth.example.com/jwks/',
				clientId: 'nodebb',
				issuer: 'https://auth.example.com/application/o/nodebb/',
			}, 'token', 'nonce-1'),
			/Unable to find OIDC signing key/
		);
	} finally {
		restore();
	}
});

test('ID token verification rejects multi-audience token without matching authorized party', async () => {
	const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const signingJwk = publicKey.export({ format: 'jwk' });
	signingJwk.kid = 'signing-key';
	signingJwk.use = 'sig';
	signingJwk.alg = 'RS256';

	const { oidc, restore } = loadOidcForIdToken({
		header: { alg: 'RS256', kid: 'signing-key' },
		keys: [signingJwk],
		claims: {
			sub: 'sub-1',
			nonce: 'nonce-1',
			aud: ['nodebb', 'other-client'],
			azp: 'other-client',
		},
	});
	try {
		await assert.rejects(
			oidc.verifyIdToken({
				jwksUri: 'https://auth.example.com/jwks/',
				clientId: 'nodebb',
				issuer: 'https://auth.example.com/application/o/nodebb/',
			}, 'token', 'nonce-1'),
			/authorized party/
		);
	} finally {
		restore();
	}
});

test('ID token verification rejects single-audience token with mismatched authorized party', async () => {
	const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const signingJwk = publicKey.export({ format: 'jwk' });
	signingJwk.kid = 'signing-key';
	signingJwk.use = 'sig';
	signingJwk.alg = 'RS256';

	const { oidc, restore } = loadOidcForIdToken({
		header: { alg: 'RS256', kid: 'signing-key' },
		keys: [signingJwk],
		claims: {
			sub: 'sub-1',
			nonce: 'nonce-1',
			aud: 'nodebb',
			azp: 'other-client',
		},
	});
	try {
		await assert.rejects(
			oidc.verifyIdToken({
				jwksUri: 'https://auth.example.com/jwks/',
				clientId: 'nodebb',
				issuer: 'https://auth.example.com/application/o/nodebb/',
			}, 'token', 'nonce-1'),
			/authorized party/
		);
	} finally {
		restore();
	}
});

test('ID token verification accepts multi-audience token with matching authorized party', async () => {
	const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const signingJwk = publicKey.export({ format: 'jwk' });
	signingJwk.kid = 'signing-key';
	signingJwk.use = 'sig';
	signingJwk.alg = 'RS256';

	const { oidc, restore } = loadOidcForIdToken({
		header: { alg: 'RS256', kid: 'signing-key' },
		keys: [signingJwk],
		claims: {
			sub: 'sub-1',
			nonce: 'nonce-1',
			aud: ['nodebb', 'other-client'],
			azp: 'nodebb',
		},
	});
	try {
		const claims = await oidc.verifyIdToken({
			jwksUri: 'https://auth.example.com/jwks/',
			clientId: 'nodebb',
			issuer: 'https://auth.example.com/application/o/nodebb/',
		}, 'token', 'nonce-1');
		assert.equal(claims.sub, 'sub-1');
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

test('logout token verification accepts signed back-channel logout event', async () => {
	const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const signingJwk = publicKey.export({ format: 'jwk' });
	signingJwk.kid = 'signing-key';
	signingJwk.use = 'sig';
	signingJwk.alg = 'RS256';

	const { oidc, restore } = loadOidcForLogoutToken({
		header: { alg: 'RS256', kid: 'signing-key' },
		keys: [signingJwk],
		claims: {
			iss: 'https://auth.example.com/application/o/nodebb/',
			aud: 'nodebb',
			sub: 'sub-1',
			sid: 'sid-1',
			iat: Math.floor(Date.now() / 1000),
			jti: 'logout-1',
			events: {
				'http://schemas.openid.net/event/backchannel-logout': {},
			},
		},
	});
	try {
		const claims = await oidc.verifyLogoutToken({
			jwksUri: 'https://auth.example.com/jwks/',
			clientId: 'nodebb',
			issuer: 'https://auth.example.com/application/o/nodebb/',
		}, 'logout-token');
		assert.equal(claims.sub, 'sub-1');
		assert.equal(claims.sid, 'sid-1');
		assert.equal(claims.jti, 'logout-1');
	} finally {
		restore();
	}
});

test('logout token verification rejects missing logout event', async () => {
	const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const signingJwk = publicKey.export({ format: 'jwk' });
	signingJwk.kid = 'signing-key';
	signingJwk.use = 'sig';
	signingJwk.alg = 'RS256';

	const { oidc, restore } = loadOidcForLogoutToken({
		header: { alg: 'RS256', kid: 'signing-key' },
		keys: [signingJwk],
		claims: {
			sub: 'sub-1',
			sid: 'sid-1',
			iat: Math.floor(Date.now() / 1000),
			jti: 'logout-1',
			nonce: 'not-allowed',
			events: {},
		},
	});
	try {
		await assert.rejects(
			oidc.verifyLogoutToken({
				jwksUri: 'https://auth.example.com/jwks/',
				clientId: 'nodebb',
				issuer: 'https://auth.example.com/application/o/nodebb/',
			}, 'logout-token'),
			/missing the back-channel logout event/
		);
	} finally {
		restore();
	}
});

test('logout token verification rejects nonce', async () => {
	const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const signingJwk = publicKey.export({ format: 'jwk' });
	signingJwk.kid = 'signing-key';
	signingJwk.use = 'sig';
	signingJwk.alg = 'RS256';

	const { oidc, restore } = loadOidcForLogoutToken({
		header: { alg: 'RS256', kid: 'signing-key' },
		keys: [signingJwk],
		claims: {
			sub: 'sub-1',
			iat: Math.floor(Date.now() / 1000),
			jti: 'logout-1',
			nonce: 'not-allowed',
			events: {
				'http://schemas.openid.net/event/backchannel-logout': {},
			},
		},
	});
	try {
		await assert.rejects(
			oidc.verifyLogoutToken({
				jwksUri: 'https://auth.example.com/jwks/',
				clientId: 'nodebb',
				issuer: 'https://auth.example.com/application/o/nodebb/',
			}, 'logout-token'),
			/must not contain nonce/
		);
	} finally {
		restore();
	}
});
