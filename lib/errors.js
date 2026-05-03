'use strict';

class AuthentikOidcError extends Error {
	constructor(code, message, level = 'warn') {
		super(message);
		this.name = 'AuthentikOidcError';
		this.code = code;
		this.level = level;
	}
}

module.exports = {
	AuthentikOidcError,
	fail(code, message, level) {
		return new AuthentikOidcError(code, message, level);
	},
};
