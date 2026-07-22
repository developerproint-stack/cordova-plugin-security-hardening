package com.proint.security;

import java.io.File;

public class XposedDetector {

    private XposedDetector() {
    }

    /**
     * Detect Xposed Framework
     */
    public static boolean detect() {

        // Check XposedBridge class
        try {

            Class.forName("de.robv.android.xposed.XposedBridge");

            return true;

        } catch (Throwable ignored) {
        }

        // Check Xposed JAR
        try {

            File file = new File("/system/framework/XposedBridge.jar");

            if (file.exists()) {

                return true;

            }

        } catch (Exception ignored) {
        }

        return false;

    }

}