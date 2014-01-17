"use strict";
var Buffer = require('buffer').Buffer;
var net = require('net');
var GRE = require('./gre').GRE;
var PPP = require('./ppp').PPP;
var ip2long = require('./util').ip2long;
var EventEmitter = require('events').EventEmitter;
var inherits = require('./util').inherits;

this.PPTP = PPTP;

function PPTP() {
	this.controlServer = net.createServer(function(socket) {
		new Client(this, socket);
	}.bind(this));
	this.gre = new GRE;
}

inherits(PPTP, EventEmitter, {
	listen: function(addr, cb) {
		if (arguments.length === 1) {
			cb = addr;
			addr = undefined;
		}
		this.controlServer.listen(1723, addr, cb);
		this.gre.listen();
	},
});

function Client(server, controlSocket) {
	this.controlSocket = controlSocket;
	this.state = 0;

	// Parse control stream
	var buffers = [];
	controlSocket.on('data', function(data) {
		// Get length field
		if (data.length) {
			buffers.push(data);
		}
		if (buffers[0].length === 1) { // as if
			if (buffers.length > 1) {
				var tmp = new Buffer(2);
				tmp[0] = buffers[0][0];
				tmp[1] = buffers[1][0];
				buffers[0] = tmp;
				buffers[1] = buffers[1].slice(1);
			}
		}
		if (buffers[0].length < 2) {
			return;
		}
		var len = buffers[0].readUInt16BE(0, true);
		var message;
		for (var ii = 0; ii < buffers.length; ++ii) {
			len -= buffers[ii].length;
			if (len === 0 && ii === 0) {
				// TODO: Reassemble chunks
				message = buffers.shift();
				break;
			} else {
				return this.terminate();
			}
		}

		// Got a message
		if (message.readUInt16BE(2) !== 1) {
			return this.terminate('Unknown control type');
		}
		if (message.readUInt32BE(4) !== 0x1a2b3c4d) {
			return this.terminate('Invalid magic cookie');
		}

		// Control message type
		switch (message.readUInt16BE(8)) {
			case 1: // Start-Control-Connection-Request
				if (this.state !== 0) {
					return this.terminate('Invalid state');
				} else if (message.readUInt16BE(12) !== 256) {
					return this.terminate('Unknown version');
				}
				this.state = 1;

				var response = new Buffer(156);
				response.fill(0);
				response.writeUInt16BE(156, 0);
				response.writeUInt16BE(1, 2);
				response.writeUInt32BE(0x1a2b3c4d, 4);
				response.writeUInt16BE(2, 8); // Start-Control-Connection-Reply
				response.writeUInt16BE(256, 12);
				response.writeUInt8(1, 14);
				response.writeUInt16BE(1, 24);
				controlSocket.write(response);
				break;

			case 7: // Outgoing-Call-Request
				if (this.state !== 1) {
					return this.terminate('Invalid state');
				}
				var peerCallId = message.readUInt16BE(12);
				var callId = (Math.random() * 0x100000000) & 0xffff;
				var call = server.gre.open(controlSocket.localAddress, controlSocket.remoteAddress, callId, peerCallId);
				var ppp = new PPP(call, '10.0.1.1', '10.0.1.2');
				server.emit('tunnel', ppp);

				var response = new Buffer(32);
				response.fill(0);
				response.writeUInt16BE(32, 0);
				response.writeUInt16BE(1, 2);
				response.writeUInt32BE(0x1a2b3c4d, 4);
				response.writeUInt16BE(8, 8); // Outgoing-Call-Reply
				response.writeUInt16BE(callId, 12);
				response.writeUInt16BE(peerCallId, 14);
				response.writeUInt8(1, 16);
				response.writeUInt32BE(100000000, 20); // connection speed
				response.writeUInt16BE(64, 24); // window
				controlSocket.write(response);
				break;					
		}
	}.bind(this));
}
