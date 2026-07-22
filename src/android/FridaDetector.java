package com.proint.security;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;

public class FridaDetector {

    private FridaDetector() {
    }

    /**
     * Full Frida Detection
     */
    public static boolean detect() {

        return detectFrida()
                || detectFridaProcess()
                || detectFridaPort();

    }

    /**
     * Detect loaded Frida libraries
     */
    private static boolean detectFrida() {

        try {

            String[] suspicious = {
                    "frida",
                    "gum",
                    "fridaserver"
            };

            BufferedReader br = new BufferedReader(
                    new FileReader("/proc/self/maps"));

            String line;

            while ((line = br.readLine()) != null) {

                for (String s : suspicious) {

                    if (line.contains(s)) {

                        br.close();

                        return true;

                    }

                }

            }

            br.close();

        } catch (Exception ignored) {
        }

        return false;

    }

    /**
     * Detect frida-server process
     */
    private static boolean detectFridaProcess() {

        try {

            java.lang.Process process = Runtime.getRuntime().exec("ps");

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(
                            process.getInputStream()));

            String line;

            while ((line = reader.readLine()) != null) {

                if (line.contains("frida")
                        || line.contains("frida-server")
                        || line.contains("gum")) {

                    try {
                        reader.close();
                    } catch (Exception ignored) {
                    }

                    return true;

                }

            }

            try {
                reader.close();
            } catch (Exception ignored) {
            }

        } catch (Exception ignored) {
        }

        return false;

    }

    /**
     * Detect default Frida ports
     */
    private static boolean detectFridaPort() {

        try {

            java.lang.Process process = Runtime.getRuntime().exec("netstat -an");

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(
                            process.getInputStream()));

            String line;

            while ((line = reader.readLine()) != null) {

                if (line.contains(":27042")
                        || line.contains(":27043")) {

                    try {
                        reader.close();
                    } catch (Exception ignored) {
                    }

                    return true;

                }

            }

            try {
                reader.close();
            } catch (Exception ignored) {
            }

        } catch (Exception ignored) {
        }

        return false;

    }

}