package com.proint.security;

import android.os.Build;

import java.io.File;
import java.util.Locale;

public class EmulatorDetector {

    private EmulatorDetector() {
    }

    /**
     * Returns true if the device shows multiple strong emulator indicators.
     *
     * The detector intentionally avoids weak indicators such as:
     * - "unknown"
     * - "test-keys"
     * - generic Android brand values
     *
     * These values can legitimately exist on real devices.
     */
    public static boolean isEmulator() {
        return getEmulatorScore() >= 3;
    }

    /**
     * Calculates emulator score based on common emulator indicators.
     *
     * Strong indicators are weighted higher.
     */
    public static int getEmulatorScore() {

        int score = 0;

        // ==========================================================
        // Build Fingerprint
        // ==========================================================

        String fingerprint = safe(Build.FINGERPRINT);

        if (fingerprint.contains("generic")) {
            score += 2;
        }

        if (fingerprint.contains("emulator")) {
            score += 2;
        }

        if (fingerprint.contains("goldfish")) {
            score += 2;
        }

        if (fingerprint.contains("ranchu")) {
            score += 2;
        }

        if (fingerprint.contains("sdk_gphone")) {
            score += 2;
        }

        // ==========================================================
        // Model
        // ==========================================================

        String model = safe(Build.MODEL);

        if (model.contains("sdk")) {
            score += 2;
        }

        if (model.contains("emulator")) {
            score += 2;
        }

        if (model.contains("android sdk")) {
            score += 2;
        }

        if (model.contains("google_sdk")) {
            score += 2;
        }

        // ==========================================================
        // Manufacturer
        // ==========================================================

        String manufacturer = safe(Build.MANUFACTURER);

        if (manufacturer.contains("genymotion")) {
            score += 2;
        }

        // ==========================================================
        // Brand
        // ==========================================================

        String brand = safe(Build.BRAND);

        if (brand.startsWith("generic")) {
            score += 1;
        }

        // ==========================================================
        // Device
        // ==========================================================

        String device = safe(Build.DEVICE);

        if (device.contains("generic")) {
            score += 2;
        }

        if (device.contains("emulator")) {
            score += 2;
        }

        if (device.contains("goldfish")) {
            score += 2;
        }

        if (device.contains("ranchu")) {
            score += 2;
        }

        if (device.contains("vbox")) {
            score += 2;
        }

        if (device.contains("sdk_gphone")) {
            score += 2;
        }

        // ==========================================================
        // Hardware
        // ==========================================================

        String hardware = safe(Build.HARDWARE);

        if (hardware.contains("goldfish")) {
            score += 2;
        }

        if (hardware.contains("ranchu")) {
            score += 2;
        }

        if (hardware.contains("vbox")) {
            score += 2;
        }

        if (hardware.contains("qemu")) {
            score += 2;
        }

        // ==========================================================
        // Product
        // ==========================================================

        String product = safe(Build.PRODUCT);

        if (product.contains("sdk")) {
            score += 2;
        }

        if (product.contains("emulator")) {
            score += 2;
        }

        if (product.contains("simulator")) {
            score += 2;
        }

        if (product.contains("vbox")) {
            score += 2;
        }

        if (product.contains("goldfish")) {
            score += 2;
        }

        if (product.contains("ranchu")) {
            score += 2;
        }

        // ==========================================================
        // Common Emulator Files
        // ==========================================================

        if (exists("/dev/qemu_pipe")) {
            score += 2;
        }

        if (exists("/dev/qemu_trace")) {
            score += 2;
        }

        if (exists("/system/bin/qemu-props")) {
            score += 2;
        }

        String host = safe(Build.HOST);

        if (host.contains("kvm")) {
            score += 3;
        }

        /*
         * Do not use /system/bin/microdroid as a standalone
         * emulator indicator. It can exist in legitimate Android
         * environments.
         */

        // ==========================================================
        // Return Score
        // ==========================================================

        return score;
    }

    /**
     * Checks whether a file/path exists.
     */
    private static boolean exists(String path) {

        try {

            return new File(path).exists();

        } catch (Exception e) {

            return false;

        }
    }

    /**
     * Safely converts Build values to lowercase.
     */
    private static String safe(String value) {

        return value == null
                ? ""
                : value.toLowerCase(Locale.US);

    }
}