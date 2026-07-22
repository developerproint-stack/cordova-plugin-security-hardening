package com.proint.security;

import android.app.Activity;
import android.content.Context;

import androidx.annotation.NonNull;

import com.google.android.gms.common.GoogleApiAvailabilityLight;
import com.google.android.gms.tasks.Task;
import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import com.google.android.play.core.integrity.IntegrityTokenResponse;

public class PlayIntegrityManager {

    public interface Listener {

        void onSuccess(String integrityToken);

        void onFailure(int code, String message);

    }

    public static final int ERROR_PLAY_SERVICES = 1001;
    public static final int ERROR_REQUEST_FAILED = 1002;
    public static final int ERROR_INVALID_NONCE = 1003;

    private final Context context;
    private final IntegrityManager integrityManager;

    public PlayIntegrityManager(Activity activity) {

        context = activity.getApplicationContext();

        integrityManager = IntegrityManagerFactory.create(context);

    }

    public void requestToken(
            @NonNull String nonce,
            Listener listener) {

        if (nonce == null || nonce.trim().isEmpty()) {
            listener.onFailure(
                    ERROR_INVALID_NONCE,
                    "Nonce is empty");
            return;
        }

        int playServiceStatus = GoogleApiAvailabilityLight
                .getInstance()
                .isGooglePlayServicesAvailable(context);

        if (playServiceStatus != 0) {

            listener.onFailure(
                    ERROR_PLAY_SERVICES,
                    "Google Play Services not available");

            return;
        }

        IntegrityTokenRequest request = IntegrityTokenRequest
                .builder()
                .setNonce(nonce)
                .build();

        Task<IntegrityTokenResponse> task = integrityManager.requestIntegrityToken(request);

        task.addOnSuccessListener(response -> {

            String token = response.token();

            listener.onSuccess(token);

        });

        task.addOnFailureListener(e -> {

            listener.onFailure(
                    ERROR_REQUEST_FAILED,
                    e.getMessage());

        });

    }

}