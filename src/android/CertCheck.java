package com.proint.security;

import android.AssetHashUtil;
import android.CertificateUtil;
import android.DebuggerDetector;
import android.FridaDetector;
import android.PlayIntegrityManager;
import android.XposedDetector;
import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class CertCheck extends CordovaPlugin {

    private static final String TAG = "CertCheck";

    public static final String ACTION_VALIDATE_CERT = "validateCert";
    public static final String ACTION_VALIDATE_WWW = "validateWwwHashes";
    public static final String ACTION_FULL_CHECK = "runFullCheck";
    public static final String ACTION_PLAY_INTEGRITY = "requestPlayIntegrityToken";
    public static final String ACTION_START_FRIDA_MONITOR = "startFridaMonitor";

    private static boolean fridaMonitorRunning = false;

    @Override
    public boolean execute(
            String action,
            JSONArray args,
            CallbackContext callback)
            throws JSONException {

        switch (action) {

            case ACTION_VALIDATE_CERT:

                validateCertificate(args, callback);
                return true;

            case ACTION_VALIDATE_WWW:

                validateAssets(args, callback);
                return true;

            case ACTION_FULL_CHECK:

                JSONObject options = args.getJSONObject(0);
                runFullCheck(options, callback);
                return true;

            case ACTION_PLAY_INTEGRITY:

                String nonce = args.getString(0);

                requestPlayIntegrityToken(
                        nonce,
                        callback);

                return true;

            case ACTION_START_FRIDA_MONITOR:

                startFridaMonitor();

                callback.success("FRIDA_MONITOR_STARTED");

                return true;

            default:

                callback.error("Unknown action : " + action);

                return false;

        }

    }

    // ==========================================================
    // Validate Certificate
    // ==========================================================

    private void validateCertificate(
            JSONArray args,
            CallbackContext callback)
            throws JSONException {

        String expected = args.getString(0);

        String actual = CertificateUtil.getCertificateSHA256(
                cordova.getActivity());

        if (actual == null) {

            callback.error("Unable to read certificate");

            return;

        }

        if (expected.equalsIgnoreCase(actual)) {

            callback.success("MATCHED");

        } else {

            callback.error("MISMATCH:" + actual);

        }

    }

    // ==========================================================
    // Validate WWW
    // ==========================================================

    private void validateAssets(
            JSONArray args,
            CallbackContext callback)
            throws JSONException {

        String manifest = args.getString(0);

        boolean ok = AssetHashUtil.validateWwwHashes(
                cordova.getActivity(),
                manifest);

        if (ok) {

            callback.success("WWW_OK");

        } else {

            callback.error("WWW_MISMATCH");

        }

    }

    // ==========================================================
    // Full Security Check
    // ==========================================================

    private void runFullCheck(
            JSONObject options,
            CallbackContext callback) {

        try {

            String expectedSHA256 = options.optString(
                    "expectedSHA256",
                    null);

            String wwwManifest = options.optString(
                    "wwwHashManifest",
                    null);

            boolean frida = FridaDetector.detect();

            boolean xposed = XposedDetector.detect();

            boolean debugger = DebuggerDetector.detect();

            if (frida || xposed || debugger) {

                JSONObject obj = new JSONObject();

                obj.put("frida", frida);
                obj.put("xposed", xposed);
                obj.put("debugger", debugger);

                callback.error(obj.toString());

                return;

            }

            if (expectedSHA256 != null) {

                String actual = CertificateUtil.getCertificateSHA256(
                        cordova.getActivity());

                if (!expectedSHA256.equalsIgnoreCase(actual)) {

                    callback.error(
                            "CERT_MISMATCH:" + actual);

                    return;

                }

            }

            if (wwwManifest != null) {

                boolean ok = AssetHashUtil.validateWwwHashes(
                        cordova.getActivity(),
                        wwwManifest);

                if (!ok) {

                    callback.error("WWW_MISMATCH");

                    return;

                }

            }

            callback.success("ALL_OK");

        } catch (Exception ex) {

            Log.e(TAG,
                    "runFullCheck",
                    ex);

            callback.error(
                    "ERROR:" + ex.getMessage());

        }

    }
    // ==========================================================
    // Play Integrity
    // ==========================================================

    private void requestPlayIntegrityToken(
            String nonce,
            CallbackContext callback) {

        PlayIntegrityManager manager = new PlayIntegrityManager(
                cordova.getActivity());

        manager.requestToken(
                nonce,
                new PlayIntegrityManager.Listener() {

                    @Override
                    public void onSuccess(String token) {

                        callback.success(token);

                    }

                    @Override
                    public void onFailure(int code, String message) {

                        try {

                            JSONObject obj = new JSONObject();

                            obj.put("code", code);
                            obj.put("message", message);

                            callback.error(obj.toString());

                        } catch (Exception ex) {

                            callback.error(message);

                        }

                    }

                });
    }
    // ==========================================================
    // Frida Background Monitor
    // ==========================================================

    private void startFridaMonitor() {

        if (fridaMonitorRunning) {
            return;
        }

        fridaMonitorRunning = true;

        Thread monitor = new Thread(() -> {

            while (true) {

                try {

                    if (FridaDetector.detect()) {

                        Log.e(TAG,
                                "Frida detected.");

                        forceCloseApp();

                        break;

                    }

                    Thread.sleep(3000);

                } catch (Exception ex) {

                    Log.e(TAG,
                            "Frida monitor error",
                            ex);

                }

            }

        });

        monitor.setName("FridaMonitor");
        monitor.setDaemon(true);
        monitor.start();
    }

    // ==========================================================
    // Force Close
    // ==========================================================

    private void forceCloseApp() {

        cordova.getActivity().runOnUiThread(() -> {

            try {

                cordova.getActivity().finishAffinity();

            } catch (Exception ignored) {
            }

            try {

                android.os.Process.killProcess(
                        android.os.Process.myPid());

            } catch (Exception ignored) {
            }

            try {

                System.exit(0);

            } catch (Exception ignored) {
            }

        });

    }
}