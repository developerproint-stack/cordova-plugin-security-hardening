package com.proint.security;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateUtil {

    private CertificateUtil() {
    }

    public static String getCertificateSHA256(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo pkg;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkg = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
                Signature[] signatures = pkg.signingInfo.getApkContentsSigners();

                if (signatures == null || signatures.length == 0)
                    return null;

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(signatures[0].toByteArray());
                return bytesToHex(md.digest());
            } else {
                pkg = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
                Signature[] signatures = pkg.signatures;

                if (signatures == null || signatures.length == 0)
                    return null;

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(signatures[0].toByteArray());
                return bytesToHex(md.digest());
            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b).toUpperCase();
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}