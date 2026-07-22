package com.proint.security;

import android.content.Context;
import android.content.res.AssetManager;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.util.Iterator;

public class AssetHashUtil {

    private AssetHashUtil() {
    }

    public static boolean validateWwwHashes(
            Context context,
            String manifestJson) {

        try {

            JSONObject manifest = new JSONObject(manifestJson);

            Iterator<String> iterator = manifest.keys();

            while (iterator.hasNext()) {

                String assetPath = iterator.next();

                String expectedHash = manifest.getString(assetPath);

                String actualHash = calculateAssetSHA256(
                        context,
                        assetPath);

                if (actualHash == null) {
                    return false;
                }

                if (!expectedHash.equalsIgnoreCase(actualHash)) {
                    return false;
                }

            }

            return true;

        } catch (Exception ex) {

            ex.printStackTrace();

            return false;

        }

    }

    private static String calculateAssetSHA256(
            Context context,
            String assetPath) throws Exception {

        AssetManager assetManager = context.getAssets();

        InputStream is = assetManager.open(assetPath);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] buffer = new byte[8192];

        int read;

        while ((read = is.read(buffer)) != -1) {

            digest.update(buffer, 0, read);

        }

        is.close();

        return bytesToHex(digest.digest());

    }

    private static String bytesToHex(byte[] bytes) {

        StringBuilder sb = new StringBuilder();

        for (byte b : bytes) {

            sb.append(String.format("%02X", b));

        }

        return sb.toString();

    }

}