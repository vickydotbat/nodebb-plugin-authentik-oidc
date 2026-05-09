'use strict';

const dns = require('node:dns');
const dnsPromises = dns.promises;
const http = require('node:http');
const https = require('node:https');
const { isBlockedHost, isBlockedIp } = require('./net-safety');

const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_MAX_REDIRECTS = 3;

async function requestJson(url, options = {}) {
	const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
	const maxBodyBytes = options.maxBodyBytes || DEFAULT_MAX_BODY_BYTES;
	const maxRedirects = options.maxRedirects === undefined ? DEFAULT_MAX_REDIRECTS : options.maxRedirects;
	const targetUrl = await safeRequestUrl(url);
	if (maxRedirects < 0) {
		throw new Error('Too many redirects while requesting JSON');
	}
	const response = await requestText(targetUrl, options, timeoutMs, maxBodyBytes);
	if (response.status >= 300 && response.status < 400) {
		const location = response.headers.location;
		if (!location) {
			throw new Error(`HTTP ${response.status} from ${targetUrl}`);
		}
		const redirectUrl = new URL(location, targetUrl).toString();
		const redirectOptions = sanitizeRedirectOptions(options, targetUrl, redirectUrl);
		return await requestJson(redirectUrl, {
			...redirectOptions,
			timeoutMs,
			maxBodyBytes,
			maxRedirects: maxRedirects - 1,
		});
	}
	const contentLength = response.headers['content-length'];
	if (contentLength && parseInt(contentLength, 10) > maxBodyBytes) {
		throw new Error(`JSON response from ${targetUrl} is too large`);
	}
	const text = response.text;
	if (Buffer.byteLength(text, 'utf8') > maxBodyBytes) {
		throw new Error(`JSON response from ${targetUrl} is too large`);
	}
	let body = null;
	if (text) {
		try {
			body = JSON.parse(text);
		} catch (err) {
			throw new Error(`Expected JSON response from ${targetUrl}`);
		}
	}
	if (response.status < 200 || response.status >= 300) {
		const error = new Error(`HTTP ${response.status} from ${targetUrl}`);
		error.status = response.status;
		error.body = body;
		throw error;
	}
	return body;
}

async function requestText(urlValue, options, timeoutMs, maxBodyBytes) {
	const url = new URL(urlValue);
	const client = url.protocol === 'https:' ? https : http;
	return await new Promise((resolve, reject) => {
		let settled = false;
		const failRequest = (err) => {
			if (settled) {
				return;
			}
			settled = true;
			reject(err);
		};
		const req = client.request(url, {
			method: options.method || 'GET',
			headers: {
				accept: 'application/json',
				...(options.headers || {}),
			},
			lookup: validatedLookup,
		}, (res) => {
			const chunks = [];
			let size = 0;
			res.setEncoding('utf8');
			res.on('data', (chunk) => {
				size += Buffer.byteLength(chunk, 'utf8');
				if (size > maxBodyBytes) {
					failRequest(new Error(`JSON response from ${urlValue} is too large`));
					req.destroy();
					return;
				}
				chunks.push(chunk);
			});
			res.on('end', () => {
				if (settled) {
					return;
				}
				settled = true;
				resolve({
					status: res.statusCode || 0,
					headers: res.headers || {},
					text: chunks.join(''),
				});
			});
		});
		req.on('error', failRequest);
		req.setTimeout(timeoutMs, () => {
			req.destroy(new Error(`Timed out requesting JSON from ${urlValue}`));
		});
		if (options.body) {
			req.write(options.body instanceof URLSearchParams ? options.body.toString() : options.body);
		}
		req.end();
	});
}

function sanitizeRedirectOptions(options, sourceUrl, redirectUrl) {
	const sanitized = { ...options };
	const sameOrigin = new URL(sourceUrl).origin === new URL(redirectUrl).origin;
	if (sameOrigin) {
		return sanitized;
	}
	const method = String(options.method || 'GET').toUpperCase();
	if (options.body || !['GET', 'HEAD'].includes(method)) {
		throw new Error('Cross-origin redirect refused for request with sensitive payload');
	}
	if (!options.headers) {
		return sanitized;
	}
	const headers = { ...options.headers };
	for (const key of Object.keys(headers)) {
		if (['authorization', 'cookie', 'proxy-authorization'].includes(key.toLowerCase())) {
			delete headers[key];
		}
	}
	sanitized.headers = headers;
	return sanitized;
}

async function safeRequestUrl(value) {
	const url = new URL(value);
	if (url.protocol !== 'https:' && url.protocol !== 'http:') {
		throw new Error('URL must use HTTP or HTTPS');
	}
	if (isBlockedHost(url.hostname)) {
		throw new Error('URL must not target localhost or private network addresses');
	}
	const results = await dnsPromises.lookup(url.hostname, { all: true, verbatim: true });
	for (const result of results) {
		if (isBlockedIp(result.address)) {
			throw new Error('URL must not target localhost or private network addresses');
		}
	}
	return url.toString();
}

function validatedLookup(hostname, options, callback) {
	if (typeof options === 'function') {
		callback = options;
		options = {};
	}
	dnsPromises.lookup(hostname, options).then((result) => {
		const address = Array.isArray(result) ? result[0] && result[0].address : result.address;
		const family = Array.isArray(result) ? result[0] && result[0].family : result.family;
		if (isBlockedIp(address)) {
			callback(new Error('URL must not target localhost or private network addresses'));
			return;
		}
		callback(null, address, family);
	}).catch(callback);
}

module.exports = {
	requestJson,
	isBlockedHost,
	isBlockedIp,
	safeRequestUrl,
};
