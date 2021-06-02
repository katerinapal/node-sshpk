import ext_sinon from "sinon";
import ext_crypto from "crypto";
import ext_path from "path";
import ext_fs from "fs";
import imp_indexjs from "../lib/index";
import ext_tape from "tape";
"use strict";
// Copyright 2016 Joyent, Inc.  All rights reserved.

var test = ext_tape.test;

var sshpk = imp_indexjs;
var fs = ext_fs;
var path = ext_path;
var crypto = ext_crypto;
var sinon = ext_sinon;

test('parsedn', function (t) {
	var id = sshpk.Identity.parseDN('cn=Blah Corp, s=CA, c=US');
	t.strictEqual(id.type, 'user');
	t.strictEqual(id.cn, 'Blah Corp');
	t.end();
});

test('parsedn escapes', function (t) {
	var id = sshpk.Identity.parseDN('cn=what\\,something,o=b==a,c=\\US');
	t.strictEqual(id.get('cn'), 'what,something');
	t.strictEqual(id.get('o'), 'b==a');
	t.strictEqual(id.get('c'), '\\US');
	id = sshpk.Identity.parseDN('cn\\=foo=bar');
	t.strictEqual(id.get('cn=foo'), 'bar');
	t.throws(function () {
		sshpk.Identity.parseDN('cn\\\\=foo');
	});
	t.end();
});

test('fromarray', function (t) {
	var arr = [
		{ name: 'ou', value: 'foo' },
		{ name: 'ou', value: 'bar' },
		{ name: 'cn', value: 'foobar,g=' }
	];
	var id = sshpk.identityFromArray(arr);
	t.throws(function () {
		id.get('ou');
	});
	t.deepEqual(id.get('ou', true), ['foo', 'bar']);
	t.strictEqual(id.get('cn'), 'foobar,g=');
	t.strictEqual(id.toString(), 'OU=foo, OU=bar, CN=foobar\\,g=');
	t.end();
});
