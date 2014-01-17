"use strict";
var ip2long = require('./util').ip2long;
var inherits = require('./util').inherits;
var EventEmitter = require('events').EventEmitter;
this.PPP = PPP;

function parseConfigurationOptions(payload) {
	var options = {};
	for (var ii = 0; ii < payload.length;) {
		var type = payload[ii], length = payload[ii + 1];
		if (length < 2) throw new Error('Invalid length');
		var option = payload.slice(ii + 2, ii + length);
		options[type] = option;
		ii += length;
	}
	return options;
}

function serializeConfigurationOptions(options) {
	var len = 0;
	for (var ii in options) {
		len += 2 + options[ii].length;
	}
	var buffer = new Buffer(len);
	var pos = 0;
	for (var ii in options) {
		buffer.writeUInt8(ii, pos);
		buffer.writeUInt8(options[ii].length + 2, pos + 1);
		options[ii].copy(buffer, pos + 2);
		pos += 2 + options[ii].length;
	}
	return buffer;
}

function PPP(datagram, hostip, peerip) {
	EventEmitter.call(this);

	var magic = ((Math.random() * 0x100000000) & 0xffffffff) >>> 0;
	var peerMagic = 0;
	var compressFieldAddress = false;

	this.datagram = datagram;

	function sendLCPPayload(code, id, payload, ipcp) {
		var buffer = new Buffer(8 + payload.length + (compressFieldAddress ? -2 : 0));
		var offset = compressFieldAddress ? 0 : 2;
		if (!compressFieldAddress) {
			buffer.writeUInt16BE(0xff03, 0);
		}
		buffer.writeUInt16BE(ipcp ? 0x8021 : 0xc021, offset);
		buffer[offset + 2] = code;
		buffer[offset + 3] = id;
		buffer.writeUInt16BE(payload.length + 4, offset + 4);
		payload.copy(buffer, offset + 6);
		datagram.send(buffer);
	}

	// Send initial Configure-Request
	var mBuffer = new Buffer(4);
	mBuffer.writeUInt32BE(magic, 0);
	var options = {
		2: new Buffer('00000000', 'hex'),
		5: mBuffer,
		7: new Buffer(0),
		8: new Buffer(0),
	};
	setTimeout(function() {
		sendLCPPayload(1, 1, serializeConfigurationOptions(options));
	}, 10);

	datagram.on('message', function(message) {
		if (message.readUInt16BE(0) === 0xff03) {
			// 0xff03 are address & control field. if these are "compressed" they are just omitted
			message = message.slice(2);
		}

		var LCP = false;
		switch (message.readUInt16BE(0)) {
			case 0xc021: // LCP
				LCP = true;
			case 0x8021: // IPCP
				var payload = message.slice(6, message.readUInt16BE(4) + 2);
				var reqId = message.readUInt8(3);
				switch (message.readUInt8(2)) {
					case 1: // Configure-Request
						var options = parseConfigurationOptions(payload);
						var unknownOptions = {};
						var negotiateOptions = {};
						for (var ii in options) {
							if (LCP) {
								switch (Number(ii)) {
									case 2: // Async-Control-Character-Map
										break;

									case 5: // Magic-Number
										peerMagic = options[ii].readUInt32BE(0);
										break;

									case 7: // Protocol-Field-Compression
									case 8: // Address-and-Control-Field-Compression
										if (!options[7] || !options[8]) {
											// Don't trifle with only compressing one
											unknownOptions[ii] = options[ii];
										}
										break;

									case 3: // Authentication-Protocol
									default:
										unknownOptions[ii] = options[ii];
										break;
								}
							} else {
								switch (Number(ii)) {
									case 3: // IP Address
										var ip = options[ii].readUInt32BE(0);
										if (ip !== ip2long(peerip)) {
											var tmp = new Buffer(4);
											tmp.writeUInt32BE(ip2long(peerip), 0);
											negotiateOptions[ii] = tmp;
										}
										break;

									case 129: // Primary DNS
									case 131: // Secondary DNS
									default:
										unknownOptions[ii] = options[ii];
										break;
								}
							}
						}

						// Configure-Reject?
						for (var ii in unknownOptions) {
							var rejectedOptions = serializeConfigurationOptions(unknownOptions);
							sendLCPPayload(4, reqId, rejectedOptions, !LCP);
							return;
						}

						// Configure-Nak?
						for (var ii in negotiateOptions) {
							var rejectedOptions = serializeConfigurationOptions(negotiateOptions);
							sendLCPPayload(3, reqId, rejectedOptions, !LCP);
							return;
						}

						// Configure-Ack
						sendLCPPayload(2, reqId, payload, !LCP);
						if (LCP) {
							if (options[7] && options[8]) {
								this.compressFieldAddress = compressFieldAddress = true;
							}
							var tmp = new Buffer(4);
							tmp.writeUInt32BE(ip2long(hostip), 0);
							var options = {
								3: tmp,
							};
							setTimeout(function() {
								sendLCPPayload(1, 1, serializeConfigurationOptions(options), true);
							}, 100);
						}
						break;

					case 9: // Echo-Request
						if (payload.readUInt32BE(0) === peerMagic) {
							var buffer = new Buffer(4);
							buffer.writeUInt32BE(magic, 0);
							sendLCPPayload(10, reqId, buffer, !LCP);
						}
						break;
				}
				break;

			case 0x0021: // IP Packets
				this.emit('message', message.slice(2));
				break;

			case 0x2145: // "Compressed" IP packet. 0x45 is start of IP frame
				this.emit('message', message.slice(1));
				break;

			default: // Send Prot-Reject
				sendLCPPayload(8, 1, message);
				break;
		}
	}.bind(this));
}

inherits(PPP, EventEmitter, {
	send: function(data) {
		var packet = new Buffer(data.length + (this.compressFieldAddress ? 1 : 4));
		if (this.compressFieldAddress) {
			packet[0] = 0x21;
		} else {
			packet.writeUInt32BE(0xff030021,  0);
		}
		data.copy(packet, this.compressFieldAddress ? 1 : 4);
		return this.datagram.send(packet);
	},
});
