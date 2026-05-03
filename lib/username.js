'use strict';

function baseUsername(claims) {
	const raw = claims.preferred_username || claims.name || (claims.email ? claims.email.split('@')[0] : '') || 'authentik-user';
	const cleaned = String(raw)
		.normalize('NFKD')
		.replace(/[^\w .-]/g, '')
		.replace(/\s+/g, ' ')
		.trim()
		.slice(0, 40);
	return cleaned || 'authentik-user';
}

async function uniqueUsername(claims, user) {
	const base = baseUsername(claims);
	let candidate = base;
	for (let attempt = 0; attempt < 20; attempt += 1) {
		const exists = await user.getUidByUsername(candidate);
		if (!exists) {
			return candidate;
		}
		candidate = `${base}-${(attempt + 1).toString(36)}`;
	}
	return `${base}-${Date.now().toString(36)}`;
}

module.exports = {
	baseUsername,
	uniqueUsername,
};
