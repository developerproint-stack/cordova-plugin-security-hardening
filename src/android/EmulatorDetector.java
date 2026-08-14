package com.proint.security;

import android.os.Build;

import java.io.File;
import java.util.Locale;

public final class EmulatorDetector {

    private EmulatorDetector() {
    }

    /**
     * Returns true if the device shows multiple common emulator indicators.
     */
    public static boolean isEmulator() {
        int score = 0;

        // Build fingerprint
        String fingerprint = Build.FINGERPRINT != null
                ? Build.FINGERPRINT.toLowerCase(Locale.US)
                : "";

        if (fingerprint.contains("generic")
                || fingerprint.contains("unknown")
                || fingerprint.contains("emulator")
                || fingerprint.contains("test-keys")
                || fingerprint.contains("goldfish")
                || fingerprint.contains("ranchu")) {
            score += 2;
        }

        // Model
        String model = Build.MODEL != null
                ? Build.MODEL.toLowerCase(Locale.US)
                : "";

        if (model.contains("sdk")
                || model.contains("emulator")
                || model.contains("android sdk")
                || model.contains("google_sdk")
                || model.contains("virtual")) {
            score += 2;
        }

        // Manufacturer
        String manufacturer = Build.MANUFACTURER != null
                ? Build.MANUFACTURER.toLowerCase(Locale.US)
                : "";

        if (manufacturer.contains("genymotion")
                || manufacturer.contains("unknown")) {
            score += 2;
        }

        // Brand
        String brand = Build.BRAND != null
                ? Build.BRAND.toLowerCase(Locale.US)
                : "";

        if (brand.startsWith("generic")
                || brand.contains("android")
                || brand.contains("unknown")) {
            score += 1;
        }

        // Device
        String device = Build.DEVICE != null
                ? Build.DEVICE.toLowerCase(Locale.US)
                : "";

        if (device.contains("generic")
                || device.contains("emulator")
                || device.contains("goldfish")
                || device.contains("ranchu")
                || device.contains("vbox")) {
            score += 2;
        }

        // Hardware
        String hardware = Build.HARDWARE != null
                ? Build.HARDWARE.toLowerCase(Locale.US)
                : "";

        if (hardware.contains("goldfish")
                || hardware.contains("ranchu")
                || hardware.contains("vbox")
                || hardware.contains("virtual")) {
            score += 2;
        }

        // Product
        String product = Build.PRODUCT != null
                ? Build.PRODUCT.toLowerCase(Locale.US)
                : "";

        if (product.contains("sdk")
                || product.contains("emulator")
                || product.contains("simulator")
                || product.contains("vbox")
                || product.contains("goldfish")
                || product.contains("ranchu")) {
            score += 2;
        }

        // Common emulator files
        if (exists("/dev/qemu_pipe")
                || exists("/dev/qemu_trace")
                || exists("/system/bin/qemu-props")
                || exists("/system/bin/microdroid")) {
            score += 2;
        }

        /*
         * Require multiple indicators instead of a single match.
         * This reduces false positives on real devices.
         */
        return score >= 3;
    }

    private static boolean exists(String path) {
        try {
            return new File(path).exists();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Useful for debugging/testing.
     */
    public static int getEmulatorScore() {
        int score = 0;

        String fingerprint = safe(Build.FINGERPRINT);
        String model = safe(Build.MODEL);
        String manufacturer = safe(Build.MANUFACTURER);
        String brand = safe(Build.BRAND);
        String device = safe(Build.DEVICE);
        String hardware = safe(Build.HARDWARE);
        String product = safe(Build.PRODUCT);

        if (fingerprint.contains("generic")
                || fingerprint.contains("unknown")
                || fingerprint.contains("emulator")
                || fingerprint.contains("test-keys")
                || fingerprint.contains("goldfish")
                || fingerprint.contains("ranchu")) {
            score += 2;
        }

        if (model.contains("sdk")
                || model.contains("emulator")
                || model.contains("android sdk")
                || model.contains("google_sdk")
                || model.contains("virtual")) {
            score += 2;
        }

        if (manufacturer.contains("genymotion")
                || manufacturer.contains("unknown")) {
            score += 2;
        }

        if (brand.startsWith("generic")
                || brand.contains("android")
                || brand.contains("unknown")) {
            score += 1;
        }

        if (device.contains("generic")
                || device.contains("emulator")
                || device.contains("goldfish")
                || device.contains("ranchu")
                || device.contains("vbox")) {
            score += 2;
        }

        if (hardware.contains("goldfish")
                || hardware.contains("ranchu")
                || hardware.contains("vbox")
                || hardware.contains("virtual")) {
            score += 2;
        }

        if (product.contains("sdk")
                || product.contains("emulator")
                || product.contains("simulator")
                || product.contains("vbox")
                || product.contains("goldfish")
                || product.contains("ranchu")) {
            score += 2;
        }

        if (exists("/dev/qemu_pipe")
                || exists("/dev/qemu_trace")
                || exists("/system/bin/qemu-props")
                || exists("/system/bin/microdroid")) {
            score += 2;
        }

        return score;
    }

    private static String safe(String value) {
        return value == null
                ? ""
                : value.toLowerCase(Locale.US);
    }
}