import imp_errorsjs from "./errors";
import imp_Identity from "./identity";
import imp_Certificate from "./certificate";
import imp_PrivateKey from "./private-key";
import imp_Signature from "./signature";
import imp_Fingerprint from "./fingerprint";
import imp_Key from "./key";
"use strict";
// Copyright 2015 Joyent, Inc.

var Key = imp_Key;
var Fingerprint = imp_Fingerprint;
var Signature = imp_Signature;
var PrivateKey = imp_PrivateKey;
var Certificate = imp_Certificate;
var Identity = imp_Identity;
var errs = imp_errorsjs;

mod_indexjs = {
	/* top-level classes */
	Key: Key,
	parseKey: Key.parse,
	Fingerprint: Fingerprint,
	parseFingerprint: Fingerprint.parse,
	Signature: Signature,
	parseSignature: Signature.parse,
	PrivateKey: PrivateKey,
	parsePrivateKey: PrivateKey.parse,
	generatePrivateKey: PrivateKey.generate,
	Certificate: Certificate,
	parseCertificate: Certificate.parse,
	createSelfSignedCertificate: Certificate.createSelfSigned,
	createCertificate: Certificate.create,
	Identity: Identity,
	identityFromDN: Identity.parseDN,
	identityForHost: Identity.forHost,
	identityForUser: Identity.forUser,
	identityForEmail: Identity.forEmail,
	identityFromArray: Identity.fromArray,

	/* errors */
	FingerprintFormatError: errs.FingerprintFormatError,
	InvalidAlgorithmError: errs.InvalidAlgorithmError,
	KeyParseError: errs.KeyParseError,
	SignatureParseError: errs.SignatureParseError,
	KeyEncryptedError: errs.KeyEncryptedError,
	CertificateParseError: errs.CertificateParseError
};
var mod_indexjs;
export default mod_indexjs;
