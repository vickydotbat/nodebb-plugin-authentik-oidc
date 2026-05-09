'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

const { createMocks, installNodebbMocks } = require('./bootstrap');

function loadLibrary(mocks) {
	const restoreNodebb = installNodebbMocks(mocks);
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'jsonwebtoken') {
			return {};
		}
		if (request === 'passport-strategy') {
			return function Strategy() {};
		}
		if (request === 'passport') {
			return { use() {} };
		}
		if (request === './src/routes/helpers') {
			return {
				setupAdminPageRoute() {},
				setupPageRoute() {},
				setupApiRoute() {},
			};
		}
		if (request === './src/privileges') {
			return { admin: { can: async () => true } };
		}
		return originalLoad.call(this, request, parent, isMain);
	};
	delete require.cache[require.resolve('../library')];
	const library = require('../library');
	return {
		library,
		restore() {
			delete require.cache[require.resolve('../library')];
			Module._load = originalLoad;
			restoreNodebb();
		},
	};
}

test('user whitelist excludes raw OIDC identity and email fields', async () => {
	const mocks = createMocks();
	const { library, restore } = loadLibrary(mocks);
	try {
		const payload = { whitelist: [] };
		await library.whitelistUserFields(payload);
		assert.equal(payload.whitelist.includes('authentikSub'), false);
		assert.equal(payload.whitelist.includes('authentikIssuer'), false);
		assert.equal(payload.whitelist.includes('authentikLastEmail'), false);
		assert.equal(payload.whitelist.includes('authentikLinkedAt'), false);
		assert.equal(payload.whitelist.includes('authentikLastLoginAt'), false);
		assert.equal(payload.whitelist.includes('authentikLastSyncedAt'), false);
	} finally {
		restore();
	}
});
