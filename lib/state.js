'use strict';

const crypto = require('node:crypto');

const SESSION_KEY = 'authentikOidc';
const MAX_AGE_MS = 10 * 60 * 1000;

function randomString(bytes = 32) {
	return crypto.randomBytes(bytes).toString('base64url');
}

function pkceChallenge(verifier) {
	return crypto.createHash('sha256').update(verifier).digest('base64url');
}

function getStore(req) {
	req.session[SESSION_KEY] = req.session[SESSION_KEY] || {};
	return req.session[SESSION_KEY];
}

function create(req, state, { usePkce = true } = {}) {
	const stateKey = typeof state === 'string' && state.length > 0 ? state : randomString();
	const store = getStore(req);
	const nonce = randomString();
	const verifier = usePkce ? randomString(48) : '';
	store[stateKey] = {
		createdAt: Date.now(),
		nonce,
		codeVerifier: verifier,
	};
	const keys = Object.keys(store);
	if (keys.length > 5) {
		keys.sort((a, b) => store[a].createdAt - store[b].createdAt)
			.slice(0, keys.length - 5)
			.forEach(key => delete store[key]);
	}
	return {
		state: stateKey,
		nonce,
		codeVerifier: verifier,
		codeChallenge: verifier ? pkceChallenge(verifier) : '',
	};
}

function consume(req, state) {
	if (typeof state !== 'string' || !state) {
		throw new Error('Missing OIDC state');
	}
	const store = getStore(req);
	const entry = store[state];
	delete store[state];
	if (!entry) {
		throw new Error('Missing OIDC state');
	}
	if (Date.now() - entry.createdAt > MAX_AGE_MS) {
		throw new Error('Expired OIDC state');
	}
	return entry;
}

module.exports = {
	create,
	consume,
	randomString,
	pkceChallenge,
};
