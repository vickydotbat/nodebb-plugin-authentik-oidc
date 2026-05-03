'use strict';

async function requestJson(url, options = {}) {
	const timeoutMs = options.timeoutMs || 10000;
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const response = await fetch(url, {
			...options,
			signal: controller.signal,
			headers: {
				accept: 'application/json',
				...(options.headers || {}),
			},
		});
		const text = await response.text();
		let body = null;
		if (text) {
			try {
				body = JSON.parse(text);
			} catch (err) {
				throw new Error(`Expected JSON response from ${url}`);
			}
		}
		if (!response.ok) {
			const error = new Error(`HTTP ${response.status} from ${url}`);
			error.status = response.status;
			error.body = body;
			throw error;
		}
		return body;
	} finally {
		clearTimeout(timer);
	}
}

module.exports = { requestJson };
