# Usage snippet

1. Add plugin:
   cordova plugin add /path/to/cordova-plugin-security-hardening

2. Generate www manifest:
   node scripts/generate-www-hashes.js www > www-hash-manifest.json

3. At app startup (after deviceready):
   // fetch expected cert and manifest from your server (HTTPS + auth)
   CertCheck.runFullCheck({
     expectedSHA256: serverResp.cert,
     wwwHashManifest: JSON.stringify(serverResp.wwwManifest)
   }, function(ok){
     console.log('OK', ok);
   }, function(err){
     console.error('CHECK FAILED', err);
     navigator.app.exitApp();
   });
