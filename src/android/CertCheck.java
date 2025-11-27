package com.proint.security;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.util.Log;

import java.io.InputStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.security.MessageDigest;
import java.util.Iterator;

public class CertCheck extends CordovaPlugin {
    private static final String TAG = "CertCheck";

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if ("validateCert".equals(action)) {
            String expected = args.getString(0);
            String actual = getCertificateSHA256();
            if (actual == null) {
                callbackContext.error("Unable to read certificate");
                return true;
            }
            if (actual.equalsIgnoreCase(expected))
                callbackContext.success("MATCHED");
            else
                callbackContext.error("MISMATCH:" + actual);
            return true;
        }

        if ("validateWwwHashes".equals(action)) {
            String manifestJson = args.getString(0);
            boolean ok = validateWwwHashes(manifestJson);
            if (ok)
                callbackContext.success("WWW_OK");
            else
                callbackContext.error("WWW_MISMATCH");
            return true;
        }

        if ("runFullCheck".equals(action)) {
            JSONObject options = args.getJSONObject(0);
            runFullCheck(options, callbackContext);
            return true;
        }

        if ("requestPlayIntegrityToken".equals(action)) {
            String nonce = args.getString(0);
            requestPlayIntegrityToken(nonce, callbackContext);
            return true;
        }

        return false;
    }

    private void runFullCheck(JSONObject options, CallbackContext callback) {
        try {
            String expected = options.optString("expectedSHA256", null);
            String wwwManifest = options.optString("wwwHashManifest", null);
            boolean frida = detectFrida();
            boolean xposed = detectXposed();
            boolean debug = isDebuggerAttached();

            if (frida || xposed || debug) {
                JSONObject res = new JSONObject();
                res.put("frida", frida);
                res.put("xposed", xposed);
                res.put("debugger", debug);
                callback.error(res.toString());
                return;
            }

            if (expected != null) {
                String actual = getCertificateSHA256();
                if (!expected.equalsIgnoreCase(actual)) {
                    callback.error("CERT_MISMATCH:" + actual);
                    return;
                }
            }

            if (wwwManifest != null) {
                boolean ok = validateWwwHashes(wwwManifest);
                if (!ok) {
                    callback.error("WWW_MISMATCH");
                    return;
                }
            }

            // Optionally, request Play Integrity token and return it to JS for server
            // verification
            if (options.has("requestPlayIntegrity") && options.getBoolean("requestPlayIntegrity")) {
                // This is a stub: actual implementation requires Play Integrity client
                // and async flow. For demo, return a placeholder string; integrate real code in
                // production.
                callback.success("ALL_OK_NO_PLAY_TOKEN_STUB");
                return;
            }

            callback.success("ALL_OK");

        } catch (Exception e) {
            callback.error("ERROR:" + e.getMessage());
        }
    }

    private String getCertificateSHA256() {
        try {
            Activity activity = this.cordova.getActivity();
            PackageManager pm = activity.getPackageManager();
            PackageInfo pkg;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                // Android 9+
                pkg = pm.getPackageInfo(activity.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
                Signature[] signatures = pkg.signingInfo.getApkContentsSigners();

                if (signatures == null || signatures.length == 0)
                    return null;

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(signatures[0].toByteArray());
                return bytesToHex(md.digest());
            } else {
                // Android 7–8 fallback
                pkg = pm.getPackageInfo(activity.getPackageName(), PackageManager.GET_SIGNATURES);
                Signature[] signatures = pkg.signatures;

                if (signatures == null || signatures.length == 0)
                    return null;

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(signatures[0].toByteArray());
                return bytesToHex(md.digest());
            }

        } catch (Exception e) {
            Log.e(TAG, "getCertificateSHA256 fail", e);
            return null;
        }
    }

    private boolean validateWwwHashes(String manifestJson) {
        // manifestJson format: { "index.html": "AABB..", "js/main.js": "BBCC.." }
        try {
            JSONObject obj = new JSONObject(manifestJson);
            Iterator<String> keys = obj.keys();
            while (keys.hasNext()) {
                String path = keys.next();
                String expected = obj.getString(path);
                String actual = calcAssetHash(path);
                if (actual == null)
                    return false;
                if (!expected.equalsIgnoreCase(actual))
                    return false;
            }
            return true;
        } catch (Exception e) {
            Log.e(TAG, "validateWwwHashes error", e);
            return false;
        }
    }

    private String calcAssetHash(String assetPath) {
        try {
            InputStream is = this.cordova.getActivity().getAssets().open("www/" + assetPath);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[4096];
            int read;
            while ((read = is.read(buffer)) != -1)
                md.update(buffer, 0, read);
            is.close();
            return bytesToHex(md.digest());
        } catch (Exception e) {
            Log.e(TAG, "calcAssetHash error for " + assetPath, e);
            return null;
        }
    }

    private boolean detectFrida() {
        // Heuristic checks for frida server / injected frida:
        try {
            String[] suspicious = new String[] { "frida", "gum", "fridaserver" };
            BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                for (String s : suspicious)
                    if (line.contains(s)) {
                        br.close();
                        return true;
                    }
            }
            br.close();
        } catch (Exception e) {
            /* ignore */ }
        return false;
    }

    private boolean detectXposed() {
        try {
            // common Xposed classes
            Class.forName("de.robv.android.xposed.XposedBridge");
            return true;
        } catch (Throwable t) {
        }
        try {
            java.io.File f = new java.io.File("/system/framework/XposedBridge.jar");
            if (f.exists())
                return true;
        } catch (Exception e) {
        }
        return false;
    }

    private boolean isDebuggerAttached() {
        return android.os.Debug.isDebuggerConnected() || android.os.Debug.waitingForDebugger();
    }

    private void requestPlayIntegrityToken(String nonce, CallbackContext callback) {
        // STUB: implement Play Integrity API call here.
        // Production: use
        // IntegrityManagerFactory.create(activity).requestIntegrityToken(request);
        // then handle async success/failure and return the token to JS for server-side
        // verification.
        callback.success("PLAY_TOKEN_STUB");
    }

    private String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b).toUpperCase();
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
