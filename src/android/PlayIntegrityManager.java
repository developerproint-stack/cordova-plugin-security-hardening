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

        if (nonce == null || nonce.trim().isEmpty()) {

            activity.runOnUiThread(() -> listener.onFailure(
                    ERROR_INVALID_NONCE,
                    "Nonce is empty"));

            return;
        }

        int status = GoogleApiAvailabilityLight
                .getInstance()
                .isGooglePlayServicesAvailable(activity);

        if (status != ConnectionResult.SUCCESS) {

            activity.runOnUiThread(() -> listener.onFailure(
                    ERROR_PLAY_SERVICES,
                    "Google Play Services not available : " + status));

            return;
        }

        IntegrityTokenRequest request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build();

        Task<IntegrityTokenResponse> task = integrityManager.requestIntegrityToken(request);

        task.addOnSuccessListener(activity, response -> {

            String token = response.token();

            activity.runOnUiThread(() -> {

                listener.onSuccess(token);

            });

        });

        task.addOnFailureListener(activity, e -> {
            int code = ERROR_REQUEST_FAILED;
            String message;

            if (e instanceof IntegrityServiceException) {

                IntegrityServiceException ex = (IntegrityServiceException) e;

                code = ex.getErrorCode();
                message = ex.getMessage();

                Log.d(TAG,
                        "IntegrityServiceException"
                                + " Code=" + code,
                        ex);

            } else {

                message = e.toString();

                Log.d(TAG,
                        "Unknown Exception",
                        e);

            }

            final int finalCode = code;
            final String finalMessage = message;

            activity.runOnUiThread(() -> {
                listener.onFailure(finalCode, finalMessage);

            });

        });

    }

}