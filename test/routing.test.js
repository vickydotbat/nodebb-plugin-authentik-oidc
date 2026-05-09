'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createMocks, installNodebbMocks } = require('./bootstrap');

function loadRouting(mocks) {
	const restore = installNodebbMocks(mocks);
	delete require.cache[require.resolve('../lib/logger')];
	delete require.cache[require.resolve('../lib/config')];
	delete require.cache[require.resolve('../lib/routing')];
	const routing = require('../lib/routing');
	return { routing, restore };
}

test('anonymous register route redirects to oidc login when plugin is enabled', async () => {
	const mocks = createMocks();
	mocks.meta.config = {};
	mocks.state.settings.set('authentik-oidc', {
		enabled: true,
	});
	const { routing, restore } = loadRouting(mocks);
	try {
		let redirectedTo = '';
		let nextCalled = false;
		await routing.handleRegisterRoute({
			loggedIn: false,
			uid: 0,
			query: {},
			headers: {},
		}, {
			redirect(url) {
				redirectedTo = url;
			},
		}, () => {
			nextCalled = true;
		});

		assert.equal(nextCalled, false);
		assert.equal(redirectedTo, 'https://forum.example.com/auth/authentik');
	} finally {
		restore();
	}
});

test('anonymous login route redirects to oidc login when configured', async () => {
	const mocks = createMocks();
	mocks.meta.config = {};
	mocks.state.settings.set('authentik-oidc', {
		enabled: true,
		redirectLoginToProvider: true,
	});
	const { routing, restore } = loadRouting(mocks);
	try {
		let redirectedTo = '';
		let nextCalled = false;
		await routing.handleLoginRoute({
			loggedIn: false,
			uid: 0,
			query: {},
			headers: {
				'x-return-to': '/unread',
			},
		}, {
			redirect(url) {
				redirectedTo = url;
			},
		}, () => {
			nextCalled = true;
		});

		const url = new URL(redirectedTo);
		assert.equal(nextCalled, false);
		assert.equal(url.pathname, '/auth/authentik');
		assert.equal(url.searchParams.get('next'), '/unread');
	} finally {
		restore();
	}
});

test('login route stays local by default', async () => {
	const mocks = createMocks();
	mocks.meta.config = {};
	mocks.state.settings.set('authentik-oidc', {
		enabled: true,
	});
	const { routing, restore } = loadRouting(mocks);
	try {
		let nextCalled = false;
		let redirected = false;
		await routing.handleLoginRoute({
			loggedIn: false,
			uid: 0,
			query: {},
			headers: {},
		}, {
			redirect() {
				redirected = true;
			},
		}, () => {
			nextCalled = true;
		});

		assert.equal(nextCalled, true);
		assert.equal(redirected, false);
	} finally {
		restore();
	}
});

test('direct OIDC launch clears stale return targets when no explicit next is supplied', () => {
	const mocks = createMocks();
	const { routing, restore } = loadRouting(mocks);
	try {
		const payload = {
			req: {
				path: '/auth/authentik',
				query: {},
				session: {
					returnTo: '/admin/plugins/authentik-oidc',
					next: '/admin/plugins/authentik-oidc',
				},
			},
			opts: {},
		};
		const result = routing.filterAuthOptions(payload);

		assert.equal(result, payload);
		assert.equal(payload.req.session.returnTo, undefined);
		assert.equal(payload.req.session.next, undefined);
	} finally {
		restore();
	}
});

test('direct OIDC launch preserves explicit safe next target', () => {
	const mocks = createMocks();
	const { routing, restore } = loadRouting(mocks);
	try {
		const payload = {
			req: {
				path: '/auth/authentik',
				query: {
					next: '/category/2/announcements',
				},
				session: {
					returnTo: '/admin/plugins/authentik-oidc',
					next: '/admin/plugins/authentik-oidc',
				},
			},
			opts: {},
		};
		routing.filterAuthOptions(payload);

		assert.equal(payload.req.session.returnTo, '/category/2/announcements');
		assert.equal(payload.req.session.next, '/category/2/announcements');
	} finally {
		restore();
	}
});

test('anonymous register redirect preserves requested next target', async () => {
	const mocks = createMocks();
	mocks.meta.config = {};
	mocks.state.settings.set('authentik-oidc', {
		enabled: true,
	});
	const { routing, restore } = loadRouting(mocks);
	try {
		let redirectedTo = '';
		await routing.handleRegisterRoute({
			loggedIn: false,
			uid: 0,
			query: {},
			headers: {
				'x-return-to': '/topic/123/example',
			},
		}, {
			redirect(url) {
				redirectedTo = url;
			},
		}, () => {});

		const url = new URL(redirectedTo);
		assert.equal(url.pathname, '/auth/authentik');
		assert.equal(url.searchParams.get('next'), '/topic/123/example');
	} finally {
		restore();
	}
});

test('anonymous register redirect drops unsafe requested next targets', async () => {
	const mocks = createMocks();
	mocks.meta.config = {};
	mocks.state.settings.set('authentik-oidc', {
		enabled: true,
	});
	const { routing, restore } = loadRouting(mocks);
	try {
		for (const nextTarget of [
			'https://evil.example/phish',
			'//evil.example/phish',
			'/\\evil.example/phish',
			'/topic/123\r\nlocation:https://evil.example',
		]) {
			let redirectedTo = '';
			await routing.handleRegisterRoute({
				loggedIn: false,
				uid: 0,
				query: {
					next: nextTarget,
				},
				headers: {},
			}, {
				redirect(url) {
					redirectedTo = url;
				},
			}, () => {});

			const url = new URL(redirectedTo);
			assert.equal(url.pathname, '/auth/authentik');
			assert.equal(url.searchParams.has('next'), false);
		}
	} finally {
		restore();
	}
});

test('register route allows explicit local and invite-based registration flows', async () => {
	const mocks = createMocks();
	mocks.meta.config = {};
	mocks.state.settings.set('authentik-oidc', {
		enabled: true,
	});
	const { routing, restore } = loadRouting(mocks);
	try {
		for (const query of [{ local: '1' }, { token: 'invite-token' }]) {
			let nextCalled = false;
			let redirected = false;
			await routing.handleRegisterRoute({
				loggedIn: false,
				uid: 0,
				query,
				headers: {},
			}, {
				redirect() {
					redirected = true;
				},
			}, () => {
				nextCalled = true;
			});
			assert.equal(nextCalled, true);
			assert.equal(redirected, false);
		}
	} finally {
		restore();
	}
});

test('register route does not redirect when plugin is disabled', async () => {
	const mocks = createMocks();
	mocks.meta.config = {};
	const { routing, restore } = loadRouting(mocks);
	try {
		let nextCalled = false;
		await routing.handleRegisterRoute({
			loggedIn: false,
			uid: 0,
			query: {},
			headers: {},
		}, {
			redirect() {
				throw new Error('should not redirect');
			},
		}, () => {
			nextCalled = true;
		});
		assert.equal(nextCalled, true);
	} finally {
		restore();
	}
});

test('register route does not redirect when redirectRegisterToLogin is disabled', async () => {
	const mocks = createMocks();
	mocks.meta.config = {};
	mocks.state.settings.set('authentik-oidc', {
		enabled: true,
		redirectRegisterToLogin: false,
	});
	const { routing, restore } = loadRouting(mocks);
	try {
		let nextCalled = false;
		await routing.handleRegisterRoute({
			loggedIn: false,
			uid: 0,
			query: {},
			headers: {},
		}, {
			redirect() {
				throw new Error('should not redirect');
			},
		}, () => {
			nextCalled = true;
		});
		assert.equal(nextCalled, true);
	} finally {
		restore();
	}
});
