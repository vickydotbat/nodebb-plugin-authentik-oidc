'use strict';

const SENSITIVE_KEY = /secret|token|code|verifier|authorization|cookie|password|nonce|state/i;
const SENSITIVE_PARAM = /^(code|client_secret|code_verifier|access_token|refresh_token|id_token|logout_token|state|nonce)$/i;
const REDACTED = '[redacted]';

function redactString(value) {
	let output = String(value || '');
	output = redactUrls(output);
	output = output.replace(/\b(Authorization|Cookie|Proxy-Authorization)\s*:\s*[^\s,;]+(?:\s+[^\s,;]+)?/gi, `$1: ${REDACTED}`);
	output = output.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, `$1 ${REDACTED}`);
	output = output.replace(/\b(code|client_secret|code_verifier|access_token|refresh_token|id_token|logout_token|state|nonce)=([^&\s]+)/gi, `$1=${REDACTED}`);
	output = output.replace(/(["'])(code|client_secret|code_verifier|access_token|refresh_token|id_token|logout_token|state|nonce)\1\s*:\s*(["'])(.*?)\3/gi, `$1$2$1:$3${REDACTED}$3`);
	output = output.replace(/\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, REDACTED);
	return output;
}

function redactUrls(value) {
	return value.replace(/https?:\/\/[^\s"'<>]+/gi, (match) => {
		try {
			const url = new URL(match);
			for (const key of [...url.searchParams.keys()]) {
				if (SENSITIVE_PARAM.test(key)) {
					url.searchParams.set(key, REDACTED);
				}
			}
			return url.toString();
		} catch (err) {
			return match;
		}
	});
}

function redact(value) {
	if (value === null || value === undefined) {
		return value;
	}
	if (typeof value === 'string') {
		return redactString(value);
	}
	if (typeof value === 'number' || typeof value === 'boolean') {
		return value;
	}
	if (Array.isArray(value)) {
		return value.map(item => redact(item));
	}
	if (typeof value === 'object') {
		const output = {};
		Object.keys(value).forEach((key) => {
			output[key] = SENSITIVE_KEY.test(key) ? REDACTED : redact(value[key]);
		});
		return output;
	}
	return REDACTED;
}

function sanitizeErrorForLog(err) {
	return {
		code: err && err.code ? String(err.code) : 'unexpected-error',
		message: err && err.message ? redactString(err.message) : 'Unexpected OIDC login failure',
		level: err && err.level ? String(err.level) : 'error',
		stack: err && err.stack ? redactString(err.stack) : '',
	};
}

module.exports = {
	REDACTED,
	redact,
	redactString,
	sanitizeErrorForLog,
};
