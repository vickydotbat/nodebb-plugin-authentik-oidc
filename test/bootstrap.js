'use strict';

const Module = require('node:module');

function installNodebbMocks(mocks) {
	const originalLoad = Module._load;
	Module._load = function (request, parent, isMain) {
		if (request === 'winston' || request === './logger' || request === './winston') {
			return mocks.logger;
		}
		return originalLoad.call(this, request, parent, isMain);
	};

	const originalRequire = require.main.require;
	require.main.require = function (request) {
		if (request === './src/database') {
			return mocks.db;
		}
		if (request === './src/user') {
			return mocks.user;
		}
		if (request === './src/logger' || request === './src/winston') {
			return mocks.logger;
		}
		if (request.startsWith('.') || request.startsWith('/')) {
			return originalRequire.call(this, request);
		}
		throw new Error(`Unexpected NodeBB require: ${request}`);
	};

	return function restore() {
		require.main.require = originalRequire;
		Module._load = originalLoad;
	};
}

function createMocks() {
	const state = {
		nextUid: 1,
		users: new Map(),
		emailToUid: new Map(),
		subToUid: new Map(),
		objects: new Map(),
	};

	const logger = {
		info() {},
		warn() {},
		error() {},
	};

	const user = {
		async exists(uid) {
			return state.users.has(parseInt(uid, 10));
		},
		async getUidByEmail(email) {
			return state.emailToUid.get(String(email).toLowerCase()) || 0;
		},
		async getUidByUsername(username) {
			for (const [uid, data] of state.users.entries()) {
				if (data.username === username) {
					return uid;
				}
			}
			return 0;
		},
		async getUserField(uid, field) {
			return (state.users.get(parseInt(uid, 10)) || {})[field];
		},
		async setUserFields(uid, fields) {
			const data = state.users.get(parseInt(uid, 10));
			Object.assign(data, fields);
		},
		async setUserField(uid, field, value) {
			const data = state.users.get(parseInt(uid, 10));
			data[field] = value;
		},
		async create(data) {
			for (const existing of state.users.values()) {
				if (String(existing.username).toLowerCase() === String(data.username).toLowerCase()) {
					throw new Error('[[error:username-taken]]');
				}
			}
			const uid = state.nextUid;
			state.nextUid += 1;
			state.users.set(uid, { uid, ...data, 'email:confirmed': 1 });
			if (data.email) {
				state.emailToUid.set(data.email.toLowerCase(), uid);
			}
			return uid;
		},
		email: {
			async confirmByUid(uid) {
				const data = state.users.get(parseInt(uid, 10));
				data['email:confirmed'] = 1;
				if (data.email) {
					state.emailToUid.set(data.email.toLowerCase(), parseInt(uid, 10));
				}
			},
		},
	};

	const db = {
		async getObject(key) {
			if (key === 'authentik:sub:uid') {
				return Object.fromEntries(state.subToUid.entries());
			}
			return state.objects.get(key) || {};
		},
		async setObject(key, value) {
			state.objects.set(key, value);
		},
		async getObjectField(key, field) {
			if (key === 'authentik:sub:uid') {
				return state.subToUid.get(field) || null;
			}
			const object = state.objects.get(key) || {};
			return object[field] || null;
		},
		async setObjectField(key, field, value) {
			if (key === 'authentik:sub:uid') {
				state.subToUid.set(field, parseInt(value, 10));
				return;
			}
			const object = state.objects.get(key) || {};
			object[field] = value;
			state.objects.set(key, object);
		},
		async deleteObjectField(key, field) {
			if (key === 'authentik:sub:uid') {
				state.subToUid.delete(field);
			}
		},
		async getSortedSetRange(key, start, stop) {
			if (key === 'users:joindate') {
				return [...state.users.keys()].slice(start, stop + 1);
			}
			return [];
		},
		async getObjectsFields(keys, fields) {
			return keys.map((key) => {
				const uid = parseInt(String(key).replace(/^user:/, ''), 10);
				const data = state.users.get(uid) || {};
				return fields.reduce((memo, field) => {
					memo[field] = data[field];
					return memo;
				}, {});
			});
		},
	};

	return { state, user, db, logger };
}

module.exports = {
	installNodebbMocks,
	createMocks,
};
