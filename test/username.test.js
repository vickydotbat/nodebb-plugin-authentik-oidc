'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const username = require('../lib/username');

test('base username uses preferred_username and strips unsafe characters', () => {
	assert.equal(username.baseUsername({
		preferred_username: 'Bad<script> Name!',
		email: 'person@example.com',
	}), 'Badscript Name');
});

test('base username falls back to email local part', () => {
	assert.equal(username.baseUsername({ email: 'Person@example.com' }), 'Person');
});
