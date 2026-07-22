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

            PackageInfo packageInfo;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {

                packageInfo = pm.getPackageInfo(
                        context.getPackageName(),
                        PackageManager.GET_SIGNING_CERTIFICATES);

                if (packageInfo.signingInfo == null) {
                    return null;
                }

                Signature[] signatures;

                if (packageInfo.signingInfo.hasMultipleSigners()) {

                    signatures = packageInfo.signingInfo.getApkContentsSigners();

                } else {

                    signatures = packageInfo.signingInfo.getSigningCertificateHistory();

                }

                if (signatures == null || signatures.length == 0) {
                    return null;
                }

                return sha256(signatures[0]);

            } else {

                packageInfo = pm.getPackageInfo(
                        context.getPackageName(),
                        PackageManager.GET_SIGNATURES);

                Signature[] signatures = packageInfo.signatures;

                if (signatures == null || signatures.length == 0) {
                    return null;
                }

                return sha256(signatures[0]);

            }

        } catch (Exception ex) {

            ex.printStackTrace();

            return null;

        }

    }

    private static String sha256(Signature signature) throws Exception {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        Certificate cert = cf.generateCertificate(
                new java.io.ByteArrayInputStream(
                        signature.toByteArray()));

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] digest = md.digest(((X509Certificate) cert).getEncoded());

        return bytesToHex(digest);

    }

    private static String bytesToHex(byte[] bytes) {

        StringBuilder sb = new StringBuilder();

        for (byte b : bytes) {

            sb.append(String.format("%02X", b));

        }

        return sb.toString();

    }

}