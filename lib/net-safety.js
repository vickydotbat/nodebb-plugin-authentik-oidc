'use strict';

const ipaddr = require('ipaddr.js');

const BLOCKED_RANGES = new Set([
	'broadcast',
	'carrierGradeNat',
	'linkLocal',
	'loopback',
	'multicast',
	'private',
	'reserved',
	'uniqueLocal',
	'unspecified',
]);

function isBlockedHost(hostname) {
	const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
	if (host === 'localhost') {
		return true;
	}
	return isBlockedIp(host);
}

function isBlockedIp(address) {
	const ip = String(address || '').toLowerCase().replace(/^\[|\]$/g, '');
	if (!ipaddr.isValid(ip)) {
		return false;
	}
	const parsed = ipaddr.parse(ip);
	if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) {
		return isBlockedParsedIp(parsed.toIPv4Address());
	}
	return isBlockedParsedIp(parsed);
}

function isBlockedParsedIp(parsed) {
	return BLOCKED_RANGES.has(parsed.range());
}

module.exports = {
	isBlockedHost,
	isBlockedIp,
};
