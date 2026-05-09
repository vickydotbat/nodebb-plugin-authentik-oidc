'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const Module = require('node:module');

function loadHttp({
	lookup = async () => [{ address: '203.0.113.10', family: 4 }],
	httpsRequest = createRequestMock([{ body: '{}' }]).request,
	httpRequest = createRequestMock([{ body: '{}' }]).request,
} = {}) {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'node:dns' && parent && parent.filename.endsWith('/lib/http.js')) {
			return { promises: { lookup } };
		}
		if (request === 'node:https' && parent && parent.filename.endsWith('/lib/http.js')) {
			return { request: httpsRequest };
		}
		if (request === 'node:http' && parent && parent.filename.endsWith('/lib/http.js')) {
			return { request: httpRequest };
		}
		return originalLoad.call(this, request, parent, isMain);
	};
	delete require.cache[require.resolve('../lib/http')];
	const http = require('../lib/http');
	return {
		http,
		restore() {
			Module._load = originalLoad;
			delete require.cache[require.resolve('../lib/http')];
		},
	};
}

function createRequestMock(responses, { connectionLookup } = {}) {
	const calls = [];
	const request = (url, options, callback) => {
		const call = {
			url: url.toString(),
			headers: options.headers || {},
			body: '',
			lookup: options.lookup,
		};
		calls.push(call);
		const req = new EventEmitter();
		req.setTimeout = () => req;
		req.write = (chunk) => {
			call.body += chunk;
		};
		req.destroy = (err) => {
			if (err) {
				process.nextTick(() => req.emit('error', err));
			}
		};
		req.end = () => {
			const finish = () => respond(callback, responses[Math.min(calls.length - 1, responses.length - 1)] || {});
			if (connectionLookup) {
				options.lookup(new URL(url).hostname, {}, (err, address, family) => {
					if (err) {
						req.emit('error', err);
						return;
					}
					call.address = address;
					call.family = family;
					finish();
				});
				return;
			}
			process.nextTick(finish);
		};
		return req;
	};
	return { calls, request };
}

function respond(callback, response) {
	const res = new EventEmitter();
	res.statusCode = response.status || 200;
	res.headers = response.headers || {};
	res.setEncoding = () => {};
	callback(res);
	process.nextTick(() => {
		if (response.body) {
			res.emit('data', response.body);
		}
		res.emit('end');
	});
}

test('requestJson rejects DNS results that resolve to private addresses before connecting', async () => {
	const requestMock = createRequestMock([{ body: '{}' }]);
	const { http, restore } = loadHttp({
		lookup: async () => [{ address: '10.0.0.10', family: 4 }],
		httpsRequest: requestMock.request,
	});
	try {
		await assert.rejects(
			http.requestJson('https://auth.example.com/.well-known/openid-configuration'),
			/private network addresses/
		);
		assert.equal(requestMock.calls.length, 0);
	} finally {
		restore();
	}
});

test('requestJson rejects private addresses returned by the connection lookup', async () => {
	const requestMock = createRequestMock([{ body: '{"ok":true}' }], {
		connectionLookup: true,
	});
	let lookupCount = 0;
	const { http, restore } = loadHttp({
		lookup: async () => {
			lookupCount += 1;
			return lookupCount === 1 ?
				[{ address: '203.0.113.10', family: 4 }] :
				{ address: '10.0.0.10', family: 4 };
		},
		httpsRequest: requestMock.request,
	});
	try {
		await assert.rejects(
			http.requestJson('https://auth.example.com/.well-known/openid-configuration'),
			/private network addresses/
		);
		assert.equal(requestMock.calls.length, 1);
	} finally {
		restore();
	}
});

test('requestJson rejects redirects to private network targets', async () => {
	const requestMock = createRequestMock([{
		status: 302,
		headers: {
			location: 'https://127.0.0.1:9443/metadata',
		},
	}]);
	const { http, restore } = loadHttp({ httpsRequest: requestMock.request });
	try {
		await assert.rejects(
			http.requestJson('https://auth.example.com/.well-known/openid-configuration'),
			/private network addresses/
		);
		assert.deepEqual(requestMock.calls.map(call => call.url), ['https://auth.example.com/.well-known/openid-configuration']);
	} finally {
		restore();
	}
});

test('requestJson strips sensitive headers when following cross-origin redirects', async () => {
	const requestMock = createRequestMock([
		{
			status: 302,
			headers: {
				location: 'https://cdn.example.net/userinfo',
			},
		},
		{
			body: '{"ok":true}',
		},
	]);
	const { http, restore } = loadHttp({ httpsRequest: requestMock.request });
	try {
		const result = await http.requestJson('https://auth.example.com/userinfo', {
			headers: {
				authorization: 'Bearer secret-token',
				cookie: 'sid=secret',
				'x-request-id': 'safe-id',
			},
		});
		assert.deepEqual(result, { ok: true });
		assert.equal(requestMock.calls[0].headers.authorization, 'Bearer secret-token');
		assert.equal(requestMock.calls[0].headers.cookie, 'sid=secret');
		assert.equal(requestMock.calls[1].url, 'https://cdn.example.net/userinfo');
		assert.equal(requestMock.calls[1].headers.authorization, undefined);
		assert.equal(requestMock.calls[1].headers.cookie, undefined);
		assert.equal(requestMock.calls[1].headers['x-request-id'], 'safe-id');
	} finally {
		restore();
	}
});

test('requestJson rejects cross-origin redirects for requests with bodies', async () => {
	const requestMock = createRequestMock([
		{
			status: 302,
			headers: {
				location: 'https://cdn.example.net/token',
			},
		},
		{
			body: '{"ok":true}',
		},
	]);
	const { http, restore } = loadHttp({ httpsRequest: requestMock.request });
	try {
		await assert.rejects(
			http.requestJson('https://auth.example.com/token', {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
				},
				body: new URLSearchParams({
					code: 'secret-code',
					client_secret: 'secret-client-secret',
				}),
			}),
			/Cross-origin redirect/
		);
		assert.equal(requestMock.calls.length, 1);
		assert.equal(requestMock.calls[0].body, 'code=secret-code&client_secret=secret-client-secret');
	} finally {
		restore();
	}
});

test('requestJson rejects oversized JSON responses', async () => {
	const oversized = JSON.stringify({ value: 'x'.repeat(2048) });
	const requestMock = createRequestMock([{ body: oversized }]);
	const { http, restore } = loadHttp({ httpsRequest: requestMock.request });
	try {
		await assert.rejects(
			http.requestJson('https://auth.example.com/userinfo', { maxBodyBytes: 128 }),
			/too large/
		);
	} finally {
		restore();
	}
});

test('requestJson rejects full IPv6 link-local range DNS results', async () => {
	const requestMock = createRequestMock([{ body: '{}' }]);
	const { http, restore } = loadHttp({
		lookup: async () => [{ address: 'feb0::1', family: 6 }],
		httpsRequest: requestMock.request,
	});
	try {
		await assert.rejects(
			http.requestJson('https://auth.example.com/.well-known/openid-configuration'),
			/private network addresses/
		);
		assert.equal(requestMock.calls.length, 0);
	} finally {
		restore();
	}
});
