import ext_saferbuffer from "safer-buffer";
import imp_SSHBuffer from "../lib/ssh-buffer";
import ext_tape from "tape";
"use strict";
// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = ext_tape.test;
var SSHBuffer = imp_SSHBuffer;
var Buffer = ext_saferbuffer.Buffer;

test('expands on write', function(t) {
	var buf = new SSHBuffer({buffer: Buffer.alloc(8)});
	buf.writeCString('abc123');
	buf.writeInt(42);
	buf.writeString('hi there what is up');

	var out = buf.toBuffer();
	t.ok(out.length > 8);

	var buf2 = new SSHBuffer({buffer: out});
	t.strictEqual(buf2.readChar(), 97);
	t.strictEqual(buf2.readCString(), 'bc123');
	t.strictEqual(buf2.readInt(), 42);
	t.strictEqual(buf2.readString(), 'hi there what is up');
	t.end();
});
