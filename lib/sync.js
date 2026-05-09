'use strict';

const user = require.main.require('./src/user');

function stringValue(value) {
	return typeof value === 'string' ? value.trim() : '';
}

function managedFields(settings = {}) {
	const fields = [];
	if (settings.syncFullnameOnLogin) {
		fields.push('fullname');
	}
	return fields;
}

function isReservedDisplayName(value) {
	return /^(admin|administrator|moderator|mod|staff|system|root|owner)$/i.test(stringValue(value));
}

async function isPrivilegedUser(uid) {
	const fields = ['isAdmin', 'administrator', 'isAdministrator', 'isGlobalModerator', 'isModerator', 'moderator'];
	for (const field of fields) {
		const value = await user.getUserField(uid, field);
		if (value === true || value === 1 || value === '1' || value === 'true') {
			return true;
		}
	}
	return false;
}

async function syncProfile(uid, claims, settings = {}) {
	const fields = {};
	const updatedFields = [];
	const skippedFields = [];

	if (settings.syncFullnameOnLogin) {
		const fullname = stringValue(claims && claims.name);
		if (fullname) {
			if (isReservedDisplayName(fullname) && !await isPrivilegedUser(uid)) {
				skippedFields.push('fullname');
			} else {
				fields.fullname = fullname;
				updatedFields.push('fullname');
			}
		}
	}

	if (!updatedFields.length) {
		return {
			updatedFields,
			skippedFields,
			managedFields: managedFields(settings),
		};
	}

	fields.authentikLastSyncedAt = Date.now();
	await user.setUserFields(uid, fields);

	return {
		updatedFields,
		skippedFields,
		managedFields: managedFields(settings),
	};
}

module.exports = {
	isReservedDisplayName,
	managedFields,
	syncProfile,
};
