"use strict";
this.ip2long = function(ip) {
	return ip.split('.').reduce(function(nn, octet, ii) {
		return (nn << 8) | octet;
	}, 0) >>> 0;
}

this.inherits = function(inherits) {
	return function(ctor, sup, props) {
		inherits(ctor, sup);
		for (var ii in props) {
			ctor.prototype[ii] = props[ii];
		}
	}
}(require('util').inherits);
