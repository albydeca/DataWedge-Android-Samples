package com.zebra.utils;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.io.FileUtils;


public class X509Importer {
//    public static void exportX509ToFile(X509Certificate cert) throws CertificateEncodingException, IOException {
//        byte[] buf = cert.getEncoded();
////		File file = null;
//        FileUtils.writeByteArrayToFile(new File("certfile"), buf);
//
//
//    }

    public static X509Certificate importX509FromFile(File certfile) throws CertificateException, IOException {
        byte[] buf = FileUtils.readFileToByteArray(certfile);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(buf);
        return (X509Certificate)certFactory.generateCertificate(in);
    }
}
