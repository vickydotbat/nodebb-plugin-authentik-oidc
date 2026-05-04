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

async function syncProfile(uid, claims, settings = {}) {
	const fields = {};
	const updatedFields = [];

	if (settings.syncFullnameOnLogin) {
		const fullname = stringValue(claims && claims.name);
		if (fullname) {
			fields.fullname = fullname;
			updatedFields.push('fullname');
		}
	}

	if (!updatedFields.length) {
		return {
			updatedFields,
			managedFields: managedFields(settings),
		};
	}

	fields.authentikLastSyncedAt = Date.now();
	await user.setUserFields(uid, fields);

	return {
		updatedFields,
		managedFields: managedFields(settings),
	};
}

module.exports = {
	managedFields,
	syncProfile,
};
