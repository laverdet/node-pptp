"use strict";
var Buffer = require('buffer').Buffer;
var raw = require('raw-socket');
var pcap = process.platform === 'darwin' ? require('pcap') : undefined;
var util = require('util');
var EventEmitter = require('events').EventEmitter;
var inherits = require('./util').inherits;
var ip2long = require('./util').ip2long;
var os = require('os');

this.GRE = GRE;

/**
 * GRE listener and parser.
 */
function GRE() {
	this.sessions = {};
	this.pcaps = Object.create(null);
}

GRE.prototype = {
	listen: function() {
		function ondata(packet) {
			// pcap returns raw ip layer packets. Parse out GRE payload
			var src = packet.readUInt32BE(12);
			var data = packet.slice(20, packet.readUInt16BE(2) + 4);

			// Parse GRE packet
			var flags = data.readUInt16BE(0);
			if (
				(flags & 0x8000) || // checksum
				(flags & 0x4000) || // routing
				!(flags & 0x2000) || // key
				(flags & 0x0800) || // strict source
				(flags & 0x0700) || // recursion control (3 bits)
				(flags & 0x0078) || // flags (3 bits)
				(flags & 0x0007) !== 1 || // version
				data.readUInt16BE(2) !== 0x880b // protocol type
			) {
				console.error('packet dropped', flags, data);
				return;
			}

			var hasSeq = flags & 0x1000;
			var hasAck = flags & 0x0080;
			var length = data.readUInt16BE(4);
			var callId = data.readUInt16BE(6);
			var session = this.sessions[src * 0x10000 + callId];

			if (session) {
				if (hasSeq) {
					session.sendAck(data.readUInt32BE(8));
					var payloadStart = hasAck ? 16 : 12;
					session.emit('message', data.slice(payloadStart, payloadStart + length));
				}
			}
		};

		this.greSocket = raw.createSocket({
			protocol: 47,
		});
		if (process.platform !== 'darwin') { // OS X kernel intercepts GRE packets
			this.greSocket.on('message', ondata.bind(this));
		} else {
			this._ondata = ondata;
		}
	},

	greListen: function(localAddr, remoteAddr) {
		if (process.platform !== 'darwin') {
			return;
		}

		var ifs = os.networkInterfaces();
		for (var ii in ifs) {
			for (var jj in ifs[ii]) {
				if (
					(ifs[ii][jj].address === localAddr && localAddr !== remoteAddr) ||
					(ifs[ii][jj].internal && localAddr === remoteAddr)
				) {
					// Got device
					if (this.pcaps[ii]) {
						return;
					}
					var cap = this.pcaps[ii] = pcap.createSession(ii, 'ip proto gre');
					cap.on('packet', function(packet) {
						switch (packet.pcap_header.link_type) {
							case 'LINKTYPE_ETHERNET':
								return this._ondata.call(this, packet.slice(14));
							case 'LINKTYPE_NULL':
								return this._ondata.call(this, packet.slice(4));
							default:
								console.log('Unknown pcap header', packet.pcap_header.link_type);
						}
					}.bind(this));
					return;
				}
			}
		}
		throw new Error('Could not listen on '+ localAddr);
	},

	open: function(host, peer, callId, peerCallId, session) {
		this.greListen(host, peer);
		var session = ip2long(peer) * 0x10000 + callId;
		var call = new GRECall(this, peer, peerCallId, session);
		this.sessions[session] = call;
		return call;
	},
};

/**
 * A GRE session opened from GRE.open
 */
function GRECall(server, host, callId, session) {
	EventEmitter.call(this);
	this.server = server;
	this.host = host;
	this.callId = callId;
	this.session = session;
	this.seq = 0;
	this.ack = -1;
	this.nextAck = undefined;
	this.ackTick = false;
}

inherits(GRECall, EventEmitter, {
	sendAck: function(seq) {
		if (this.nextAck === undefined || seq > this.nextAck) {
			this.nextAck = seq;
			if (!this.ackTick) {
				this.ackTick = true;
				process.nextTick(function() {
					this.ackTick = false;
					if (this.nextAck > this.ack) {
						this.send();
					}
				}.bind(this));
			}
		}
	},

	close: function() {
		delete this.server.sessions[this.session];
	},

	send: function(payload) {
		if (payload && !payload.length) {
			payload = undefined;
		}
		var ack;
		if (this.nextAck > this.ack) {
			ack = this.ack = this.nextAck;
			this.nextAck = undefined;
		}
		var buffer = new Buffer(8 + (payload ? payload.length + 4 : 0) + (ack ? 4 : 0));
		buffer.fill(0);
		buffer.writeUInt16BE(0x2000 | 0x0001 | (payload ? 0x1000 : 0) | (ack ? 0x0080 : 0), 0);
		buffer.writeUInt16BE(0x880b, 2);
		if (payload) {
			buffer.writeUInt16BE(payload.length, 4);
		}
		buffer.writeUInt16BE(this.callId, 6);
		if (payload) {
			buffer.writeUInt32BE(this.seq++, 8);
			payload.copy(buffer, ack ? 16 : 12);
		}
		if (ack) {
			buffer.writeUInt32BE(ack, payload ? 12 : 8);
		}
		this.server.greSocket.send(buffer, 0, buffer.length, this.host, function(err) {
			if (err) console.error('Error sending GRE payload', err);
		});
	},
});
