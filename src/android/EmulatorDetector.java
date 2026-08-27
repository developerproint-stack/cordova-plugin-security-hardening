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
     * Weak/common values such as:
     * - unknown
     * - test-keys
     * - kvm
     * - root
     * - compiler
     *
     * are intentionally NOT used because they can exist
     * on legitimate physical devices.
     */
    public static boolean isEmulator() {
        return getEmulatorScore() >= 3;
    }

    /**
     * Calculates emulator score based on emulator-specific indicators.
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
            score += 3;
        }

        if (fingerprint.contains("ranchu")) {
            score += 3;
        }

        if (fingerprint.contains("sdk_gphone")) {
            score += 3;
        }

        if (fingerprint.contains("qemu")) {
            score += 3;
        }

        if (fingerprint.contains("virtualbox")) {
            score += 3;
        }

        if (fingerprint.contains("vmware")) {
            score += 3;
        }

        // ==========================================================
        // Model
        // ==========================================================

        String model = safe(Build.MODEL);

        if (model.contains("sdk")) {
            score += 2;
        }

        if (model.contains("emulator")) {
            score += 3;
        }

        if (model.contains("android sdk")) {
            score += 3;
        }

        if (model.contains("google_sdk")) {
            score += 3;
        }

        if (model.contains("qemu")) {
            score += 3;
        }

        if (model.contains("virtualbox")) {
            score += 3;
        }

        if (model.contains("vmware")) {
            score += 3;
        }

        // ==========================================================
        // Manufacturer
        // ==========================================================

        String manufacturer = safe(Build.MANUFACTURER);

        if (manufacturer.contains("genymotion")) {
            score += 3;
        }

        if (manufacturer.contains("qemu")) {
            score += 3;
        }

        if (manufacturer.contains("virtualbox")) {
            score += 3;
        }

        if (manufacturer.contains("vmware")) {
            score += 3;
        }

        // ==========================================================
        // Brand
        // ==========================================================

        String brand = safe(Build.BRAND);

        if (brand.startsWith("generic")) {
            score += 2;
        }

        if (brand.contains("qemu")) {
            score += 3;
        }

        if (brand.contains("virtualbox")) {
            score += 3;
        }

        if (brand.contains("vmware")) {
            score += 3;
        }

        // ==========================================================
        // Device
        // ==========================================================

        String device = safe(Build.DEVICE);

        if (device.contains("generic")) {
            score += 2;
        }

        if (device.contains("emulator")) {
            score += 3;
        }

        if (device.contains("goldfish")) {
            score += 3;
        }

        if (device.contains("ranchu")) {
            score += 3;
        }

        if (device.contains("vbox")) {
            score += 3;
        }

        if (device.contains("sdk_gphone")) {
            score += 3;
        }

        if (device.contains("qemu")) {
            score += 3;
        }

        // ==========================================================
        // Hardware
        // ==========================================================

        String hardware = safe(Build.HARDWARE);

        if (hardware.contains("goldfish")) {
            score += 3;
        }

        if (hardware.contains("ranchu")) {
            score += 3;
        }

        if (hardware.contains("vbox")) {
            score += 3;
        }

        if (hardware.contains("qemu")) {
            score += 3;
        }

        if (hardware.contains("virtualbox")) {
            score += 3;
        }

        if (hardware.contains("vmware")) {
            score += 3;
        }

        // ==========================================================
        // Product
        // ==========================================================

        String product = safe(Build.PRODUCT);

        if (product.contains("sdk")) {
            score += 2;
        }

        if (product.contains("emulator")) {
            score += 3;
        }

        if (product.contains("simulator")) {
            score += 3;
        }

        if (product.contains("vbox")) {
            score += 3;
        }

        if (product.contains("goldfish")) {
            score += 3;
        }

        if (product.contains("ranchu")) {
            score += 3;
        }

        if (product.contains("qemu")) {
            score += 3;
        }

        if (product.contains("virtualbox")) {
            score += 3;
        }

        if (product.contains("vmware")) {
            score += 3;
        }

        // ==========================================================
        // Common Emulator Files
        // ==========================================================

        if (exists("/dev/qemu_pipe")) {
            score += 3;
        }

        if (exists("/dev/qemu_trace")) {
            score += 3;
        }

        if (exists("/system/bin/qemu-props")) {
            score += 3;
        }

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