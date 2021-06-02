import imp_Certificate from "../certificate";
import imp_Signature from "../signature";
import imp_Identity from "../identity";
import imp_pemjs from "./pem";
import imp_PrivateKey from "../private-key";
import imp_Key from "../key";
import imp_utilsjs from "../utils";
import imp_algsjs from "../algs";
import ext_saferbuffer from "safer-buffer";
import ext_asn1 from "asn1";
import ext_assertplus from "assert-plus";
import imp_x509js from "./x509";
"use strict";
// Copyright 2016 Joyent, Inc.

var x509 = imp_x509js;

mod_x509pemjs = {
	read: read,
	verify: x509.verify,
	sign: x509.sign,
	write: write
};

var assert = ext_assertplus;
var asn1 = ext_asn1;
var Buffer = ext_saferbuffer.Buffer;
var algs = imp_algsjs;
var utils = imp_utilsjs;
var Key = imp_Key;
var PrivateKey = imp_PrivateKey;
var pem = imp_pemjs;
var Identity = imp_Identity;
var Signature = imp_Signature;
var Certificate = imp_Certificate;

function read(buf, options) {
	if (typeof (buf) !== 'string') {
		assert.buffer(buf, 'buf');
		buf = buf.toString('ascii');
	}

	var lines = buf.trim().split(/[\r\n]+/g);

	var m;
	var si = -1;
	while (!m && si < lines.length) {
		m = lines[++si].match(/*JSSTYLED*/
		    /[-]+[ ]*BEGIN CERTIFICATE[ ]*[-]+/);
	}
	assert.ok(m, 'invalid PEM header');

	var m2;
	var ei = lines.length;
	while (!m2 && ei > 0) {
		m2 = lines[--ei].match(/*JSSTYLED*/
		    /[-]+[ ]*END CERTIFICATE[ ]*[-]+/);
	}
	assert.ok(m2, 'invalid PEM footer');

	lines = lines.slice(si, ei + 1);

	var headers = {};
	while (true) {
		lines = lines.slice(1);
		m = lines[0].match(/*JSSTYLED*/
		    /^([A-Za-z0-9-]+): (.+)$/);
		if (!m)
			break;
		headers[m[1].toLowerCase()] = m[2];
	}

	/* Chop off the first and last lines */
	lines = lines.slice(0, -1).join('');
	buf = Buffer.from(lines, 'base64');

	return (x509.read(buf, options));
}

function write(cert, options) {
	var dbuf = x509.write(cert, options);

	var header = 'CERTIFICATE';
	var tmp = dbuf.toString('base64');
	var len = tmp.length + (tmp.length / 64) +
	    18 + 16 + header.length*2 + 10;
	var buf = Buffer.alloc(len);
	var o = 0;
	o += buf.write('-----BEGIN ' + header + '-----\n', o);
	for (var i = 0; i < tmp.length; ) {
		var limit = i + 64;
		if (limit > tmp.length)
			limit = tmp.length;
		o += buf.write(tmp.slice(i, limit), o);
		buf[o++] = 10;
		i = limit;
	}
	o += buf.write('-----END ' + header + '-----\n', o);

	return (buf.slice(0, o));
}
var mod_x509pemjs;
export default mod_x509pemjs;
