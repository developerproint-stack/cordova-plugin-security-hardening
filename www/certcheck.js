var exec = require('cordova/exec');

exports.validateCert = function(expectedSHA256, success, error) {
    exec(success, error, "CertCheck", "validateCert", [expectedSHA256]);
};

exports.validateWwwHashes = function(hashManifestJson, success, error) {
    exec(success, error, "CertCheck", "validateWwwHashes", [hashManifestJson]);
};

exports.runFullCheck = function(options, success, error) {
    // options: { expectedSHA256, wwwHashManifest, requestPlayIntegrity }
    exec(success, error, "CertCheck", "runFullCheck", [options]);
};

exports.requestPlayIntegrityToken = function(nonce, success, error) {
    exec(success, error, "CertCheck", "requestPlayIntegrityToken", [nonce]);
};
