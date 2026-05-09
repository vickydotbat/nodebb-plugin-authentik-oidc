'use strict';

const openidClient = require('openid-client');

const SESSION_KEY = 'authentikOidc';
const MAX_AGE_MS = 10 * 60 * 1000;

function getStore(req) {
	req.session[SESSION_KEY] = req.session[SESSION_KEY] || {};
	return req.session[SESSION_KEY];
}

async function create(req) {
	const stateKey = openidClient.randomState();
	const store = getStore(req);
	const nonce = openidClient.randomNonce();
	const verifier = openidClient.randomPKCECodeVerifier();
	const challenge = await openidClient.calculatePKCECodeChallenge(verifier);
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
		codeChallenge: challenge,
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
	return {
		...entry,
		state,
	};
}

module.exports = {
	create,
	consume,
};
