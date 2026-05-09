'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const netSafety = require('../lib/net-safety');

test('IP safety handles IPv4-mapped addresses through ipaddr.js range semantics', () => {
	assert.equal(netSafety.isBlockedIp('::ffff:127.0.0.1'), true);
	assert.equal(netSafety.isBlockedIp('::ffff:192.168.1.10'), true);
	assert.equal(netSafety.isBlockedIp('::ffff:8.8.8.8'), false);
});
