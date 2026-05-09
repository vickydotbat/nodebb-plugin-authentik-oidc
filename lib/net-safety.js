'use strict';

const net = require('node:net');

const BLOCKED_IPV4_RANGES = [
	[0x00000000, 0xff000000], // 0.0.0.0/8
	[0x0a000000, 0xff000000], // 10.0.0.0/8
	[0x64400000, 0xffc00000], // 100.64.0.0/10
	[0x7f000000, 0xff000000], // 127.0.0.0/8
	[0xa9fe0000, 0xffff0000], // 169.254.0.0/16
	[0xac100000, 0xfff00000], // 172.16.0.0/12
	[0xc0000000, 0xffffff00], // 192.0.0.0/24
	[0xc0000200, 0xffffff00], // 192.0.2.0/24
	[0xc0a80000, 0xffff0000], // 192.168.0.0/16
	[0xc6120000, 0xfffe0000], // 198.18.0.0/15
	[0xc6336400, 0xffffff00], // 198.51.100.0/24
	[0xcb007100, 0xffffff00], // 203.0.113.0/24
	[0xe0000000, 0xf0000000], // 224.0.0.0/4
	[0xf0000000, 0xf0000000], // 240.0.0.0/4
	[0xffffffff, 0xffffffff],
];
const BLOCKED_IPV6_RANGES = [
	[0n, 128],
	[1n, 128],
	[0xfc00n << 112n, 7],
	[0xfe80n << 112n, 10],
	[0xff00n << 112n, 8],
	[0x20010db8n << 96n, 32],
];

function isBlockedHost(hostname) {
	const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
	if (host === 'localhost' || host === '0.0.0.0' || host === '::' || host === '::1') {
		return true;
	}
	return net.isIP(host) ? isBlockedIp(host) : false;
}

function isBlockedIp(address) {
	const ip = String(address || '').toLowerCase().replace(/^\[|\]$/g, '');
	if (net.isIP(ip) === 4) {
		const value = ipv4ToNumber(ip);
		return BLOCKED_IPV4_RANGES.some(([range, mask]) => ((value & mask) >>> 0) === (range >>> 0));
	}
	if (net.isIP(ip) !== 6) {
		return false;
	}
	const value = ipv6ToBigInt(ip);
	return BLOCKED_IPV6_RANGES.some(([range, prefix]) => ipv6Matches(value, range, prefix)) ||
		ip.startsWith('::ffff:');
}

function ipv4ToNumber(ip) {
	return ip.split('.').reduce((memo, octet) => ((memo << 8) + parseInt(octet, 10)) >>> 0, 0);
}

function ipv6Matches(value, range, prefix) {
	const shift = BigInt(128 - prefix);
	return (value >> shift) === (range >> shift);
}

function ipv6ToBigInt(ip) {
	const [head, tail = ''] = ip.toLowerCase().split('::');
	const headParts = head ? head.split(':') : [];
	const tailParts = tail ? tail.split(':') : [];
	const missing = 8 - headParts.length - tailParts.length;
	const parts = [...headParts, ...Array(Math.max(missing, 0)).fill('0'), ...tailParts];
	return parts.reduce((memo, part) => (memo << 16n) + BigInt(parseInt(part || '0', 16)), 0n);
}

module.exports = {
	isBlockedHost,
	isBlockedIp,
};
