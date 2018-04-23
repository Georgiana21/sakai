package org.sakaiproject.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class RSAHelper {

    private static RSAHelper instance;

    private RSAHelper(){}

    public static RSAHelper getInstance() {
        if(instance == null)
            instance = new RSAHelper();
        return instance;
    }

    public static PublicKey getPublicKey(
            File storeFile,
            String keyStorePass,
            String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{

        FileInputStream fis = new FileInputStream(storeFile);
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, keyStorePass.toCharArray());
        PublicKey pubKey = keystore.getCertificate(alias).getPublicKey();
        return pubKey;
    }

    public static PrivateKey getPrivateKey(
            File storeFile,
            String keyStorePass,
            String alias,
            String keyPass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException{

        FileInputStream fis = new FileInputStream(storeFile);
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, keyStorePass.toCharArray());
        PrivateKey privKey = (PrivateKey)keystore.getKey(alias, keyPass.toCharArray());
        return privKey;
    }

    public static PublicKey getCertificateKey(File file) throws FileNotFoundException, CertificateException{
        FileInputStream fis = new FileInputStream(file);
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(fis);
        return certificate.getPublicKey();
    }

    public static PublicKey getCertificateKey(InputStream fis) throws CertificateException{
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(fis);
        return certificate.getPublicKey();
    }

    public static byte[] encrypt(byte[] input, Key key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        int chunkSize = 245;
        int encSize = (int) (Math.ceil(input.length/245.0)*256);
        int idx = 0;
        ByteBuffer buf = ByteBuffer.allocate(encSize);

        while (idx < input.length) {
            int len = Math.min(input.length-idx, chunkSize);
            byte[] encChunk = cipher.doFinal(input, idx, len);
            buf.put(encChunk);
            idx += len;
        }

        return buf.array();
    }

    public static byte[] decrypt(byte[] input, Key key, int size)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        int chunkSize = 256;
        int idx = 0;
        ByteBuffer buf = ByteBuffer.allocate(size);
        while(idx < input.length) {
            int len = Math.min(input.length-idx, chunkSize);
            byte[] chunk = cipher.doFinal(input, idx, len);
            buf.put(chunk);
            idx += len;
        }
        return buf.array();
    }
}
