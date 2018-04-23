package org.sakaiproject.util;

import com.neurotec.biometrics.NMatchingResult;
import com.neurotec.biometrics.NSubject;
import com.neurotec.biometrics.client.NBiometricClient;
import com.neurotec.io.NBuffer;
import com.neurotec.licensing.NLicense;
import javafx.util.Pair;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.net.URLClassLoader;
import java.security.*;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Map;

public class FingerHelper {

    private static FingerHelper instance;
    private ArrayList<NSubject> subjects = new ArrayList<NSubject>();
    final String matching = "Biometrics.FingerMatching";
    final String fingerExtraction = "Biometrics.FingerExtraction";
    NBiometricClient biometricClient;
    URLClassLoader cl;

    private FingerHelper() {
        LibraryManager.initLibraryPath();
        String path = System.getProperty("java.library.path");
        try {
            if (!NLicense.obtainComponents("/local", 5000, matching) ||
                    !NLicense.obtainComponents("/local", 5000, fingerExtraction)) {
                System.err.println("Could not obtain licenses for components: " + matching);
            }

            biometricClient = new NBiometricClient();

            //load subjects from database
            Map<String, Pair<byte[],Integer>> users = DatabaseHelper.getInstance().getUsersAndTemplate();
            for (Map.Entry<String, Pair<byte[],Integer>> entry : users.entrySet()) {
                addFingerToCache(entry.getKey(), entry.getValue().getKey(),entry.getValue().getValue());
            }

        } catch (SQLException | IOException | NoSuchPaddingException | NoSuchAlgorithmException | CertificateException | KeyStoreException | InvalidKeyException | UnrecoverableKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    public static FingerHelper getInstance(){
        if(instance == null)
            instance = new FingerHelper();
        return instance;
    }

    public byte[] getDecryptedTemplate(byte[] template, int size) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        File file = new File("C:\\tomcat\\sakai_keystore");
        PrivateKey privateKey = RSAHelper.getPrivateKey(file,"sakai_keystore_pass","sakai_keypair", "sakai_keypass");
        return RSAHelper.decrypt(template, privateKey, size);
    }

    public void addFingerToCache(String user, byte[] template, int size) throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, KeyStoreException {
        byte[] decryptedTemplate = getDecryptedTemplate(template, size);
        NBuffer buffer = new NBuffer(decryptedTemplate);
        NSubject subject = NSubject.fromMemory(buffer);
        subject.setId(user);
        subjects.add(subject);
        biometricClient.enroll(subject);
    }

    public String identifyUser(byte[] template){
        NBuffer buffer = new NBuffer(template);
        NSubject subject = NSubject.fromMemory(buffer);
        biometricClient.identify(subject);

        String user = null;
        for (NSubject s : subjects) {
            for (NMatchingResult result : subject.getMatchingResults()) {
                if (s.getId().equals(result.getId())) {
                    user = s.getId();
                    break;
                }
            }

        }

        return user;
    }
}

