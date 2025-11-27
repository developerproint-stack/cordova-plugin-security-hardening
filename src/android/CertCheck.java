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
import android.os.Process;
import android.util.Log;

import java.io.InputStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.util.Iterator;

public class CertCheck extends CordovaPlugin {
    private static final String TAG = "CertCheck";
    private static boolean fridaMonitorRunning = false;

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

        // === ADDED: start background anti-Frida monitor ===
        if ("startFridaMonitor".equals(action)) {
            startFridaMonitor();
            callbackContext.success("FRIDA_MONITOR_STARTED");
            return true;
        }
        // === END ADDED ===

        return false;
    }

    private void runFullCheck(JSONObject options, CallbackContext callback) {
        try {
            String expected = options.optString("expectedSHA256", null);
            String wwwManifest = options.optString("wwwHashManifest", null);
            boolean frida = detectFridaFull();
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
                pkg = pm.getPackageInfo(activity.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
                Signature[] signatures = pkg.signingInfo.getApkContentsSigners();

                if (signatures == null || signatures.length == 0)
                    return null;

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(signatures[0].toByteArray());
                return bytesToHex(md.digest());
            } else {
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

    // =============================================================================
    // === ADDED: FULL ANTI-FRIDA SUITE (process, libs, ports)
    // =============================================================================

    private boolean detectFridaFull() {
        return detectFrida() || detectFridaProcess() || detectFridaPort();
    }

    // original basic detection (keeping your code)
    private boolean detectFrida() {
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
        }
        return false;
    }

    // check if frida-server process is running
    private boolean detectFridaProcess() {
        try {
            Process p = Runtime.getRuntime().exec("ps");
            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                if (line.contains("frida") || line.contains("frida-server") || line.contains("gum")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    // check default frida ports
    private boolean detectFridaPort() {
        try {
            Process p = Runtime.getRuntime().exec("netstat -an");
            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                if (line.contains(":27042") || line.contains(":27043")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    // === ADDED: hard kill app ===
    private void forceCloseApp() {
        Activity a = this.cordova.getActivity();
        a.runOnUiThread(() -> {
            a.finishAffinity();
            Process.killProcess(Process.myPid());
            System.exit(0);
        });
    }

    // === ADDED: background monitor ===
    private void startFridaMonitor() {
        if (fridaMonitorRunning) {
            return; // ignore jika sudah jalan
        }
        fridaMonitorRunning = true;

        // Start thread monitor
        new Thread(() -> {
            while (true) {
                if (detectFridaFull()) {
                    forceCloseApp();
                    break;
                }
                try {
                    Thread.sleep(3000);
                } catch (Exception e) {
                }
            }
        }).start();
    }

    // =============================================================================
    // END ADDED
    // =============================================================================

    private boolean detectXposed() {
        try {
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
