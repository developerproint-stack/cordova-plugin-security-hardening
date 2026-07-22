package com.proint.security;

import android.app.Activity;
import android.util.Log;

import androidx.annotation.NonNull;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailabilityLight;
import com.google.android.gms.tasks.Task;
import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityServiceException;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import com.google.android.play.core.integrity.IntegrityTokenResponse;

public class PlayIntegrityManager {

    private static final String TAG = "PlayIntegrity";

    public interface Listener {
        void onSuccess(String integrityToken);

        void onFailure(int code, String message);
    }

    public static final int ERROR_PLAY_SERVICES = 1001;
    public static final int ERROR_REQUEST_FAILED = 1002;
    public static final int ERROR_INVALID_NONCE = 1003;

    private final Activity activity;
    private final IntegrityManager integrityManager;

    public PlayIntegrityManager(Activity activity) {

        this.activity = activity;

        integrityManager = IntegrityManagerFactory.create(activity);

    }

    public void requestToken(
            @NonNull String nonce,
            @NonNull Listener listener) {

        Log.d(TAG, "========== REQUEST START ==========");
        Log.d(TAG, "Nonce = " + nonce);

        if (nonce == null || nonce.trim().isEmpty()) {

            Log.e(TAG, "Nonce kosong");

            activity.runOnUiThread(() -> listener.onFailure(
                    ERROR_INVALID_NONCE,
                    "Nonce is empty"));

            return;
        }

        int status = GoogleApiAvailabilityLight
                .getInstance()
                .isGooglePlayServicesAvailable(activity);

        if (status != ConnectionResult.SUCCESS) {

            Log.e(TAG, "Google Play Services Error = " + status);

            activity.runOnUiThread(() -> listener.onFailure(
                    ERROR_PLAY_SERVICES,
                    "Google Play Services not available : " + status));

            return;
        }

        IntegrityTokenRequest request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build();

        Log.d(TAG, "Calling requestIntegrityToken()");

        Task<IntegrityTokenResponse> task = integrityManager.requestIntegrityToken(request);

        Log.d(TAG, "requestIntegrityToken() returned Task");

        task.addOnSuccessListener(activity, response -> {

            Log.e("PI_DEBUG", "========== SUCCESS CALLBACK ==========");

            String token = response.token();

            Log.d("PI_DEBUG", "Token = " + token);

            Log.e("PI_DEBUG",
                    "Token Length = " +
                            (token == null ? 0 : token.length()));

            activity.runOnUiThread(() -> {

                Log.e("PI_DEBUG", "Calling listener.onSuccess()");

                listener.onSuccess(token);

            });

        });

        task.addOnFailureListener(activity, e -> {
            Log.e("PI_DEBUG", "========== FAILURE CALLBACK ==========");
            int code = ERROR_REQUEST_FAILED;
            String message;

            if (e instanceof IntegrityServiceException) {

                IntegrityServiceException ex = (IntegrityServiceException) e;

                code = ex.getErrorCode();
                message = ex.getMessage();

                Log.e(TAG,
                        "IntegrityServiceException"
                                + " Code=" + code,
                        ex);

            } else {

                message = e.toString();

                Log.e(TAG,
                        "Unknown Exception",
                        e);

            }

            final int finalCode = code;
            final String finalMessage = message;

            activity.runOnUiThread(() -> {

                Log.e("PI_DEBUG", "Calling listener.onFailure()");

                listener.onFailure(finalCode, finalMessage);

            });

        });

        Log.d(TAG, "========== REQUEST SENT ==========");

    }

}