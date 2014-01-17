"use strict";
var PPTP = require('./pptp').PPTP;
var raw = require('raw-socket');

function format(buf) {
	return buf.toString('hex').replace(/([a-f0-9]{4})/g, '$1 ').replace(/((?:[a-f0-9]{4} ){8})/g, '$1\n');
}

var pptp = new PPTP;
pptp.listen();
pptp.on('tunnel', function(tunnel) {
	tunnel.on('message', function(data) {
		console.log('>   '+ format(data).replace(/\n/g, '\n    ')+ '\n');
		if (data[9] === 1 && data[20] === 8) {
			var tmp = new Buffer(data.length);
			data.copy(tmp);
			var src = tmp.readUInt32BE(12);
			tmp.writeUInt32BE(tmp.readUInt32BE(16), 12);
			tmp.writeUInt32BE(src, 16);
			// Did you know that in IPv4 swapping the src/dst does *not* change the header checksum??
			// If it did, this is how you would recalculate it.
			// tmp.writeUInt16BE(0, 10);
			// raw.writeChecksum(tmp, 10, raw.createChecksum(tmp.slice(0, 20)));
			tmp[20] = 0; // Echo reply
			tmp.writeUInt16BE(0, 22); // ICMP checksum
			raw.writeChecksum(tmp, 22, raw.createChecksum(tmp.slice(20)));

			console.log('<   '+ format(data).replace(/\n/g, '\n    ')+ '\n');
			tunnel.send(tmp);
		}
	});
});

