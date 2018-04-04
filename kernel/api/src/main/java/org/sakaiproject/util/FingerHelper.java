package org.sakaiproject.util;

import com.neurotec.biometrics.NMatchingResult;
import com.neurotec.biometrics.NSubject;
import com.neurotec.biometrics.client.NBiometricClient;
import com.neurotec.io.NBuffer;
import com.neurotec.licensing.NLicense;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class FingerHelper {

    private static FingerHelper instance;
    private ArrayList<NSubject> subjects = new ArrayList<NSubject>();
    final String matching = "Biometrics.FingerMatching";
    final String fingerExtraction = "Biometrics.FingerExtraction";
    NBiometricClient biometricClient;
    URLClassLoader cl;

    private void loadJars() {
        JarFile jarFile = null;
        try {
            URL[] urls = {new URL("jar:file:" + "C:\\tomcat\\lib\\jna-1.0.0.jar" + "!/"),
                    new URL("jar:file:" + "C:\\tomcat\\lib\\neurotec-core-1.0.0.jar" + "!/"),
                    new URL("jar:file:" + "C:\\tomcat\\lib\\neurotec-devices-1.0.0.jar" + "!/"),
                    new URL("jar:file:" + "C:\\tomcat\\lib\\neurotec-biometrics-1.0.0.jar" + "!/"),
                    new URL("jar:file:" + "C:\\tomcat\\lib\\neurotec-biometrics-client-1.0.0.jar" + "!/"),
                    new URL("jar:file:" + "C:\\tomcat\\lib\\neurotec-licensing-1.0.0.jar" + "!/"),
                    new URL("jar:file:" + "C:\\tomcat\\lib\\neurotec-licensing-1.0.0.jar" + "!/"),
                    new URL("jar:file:" + "C:\\tomcat\\lib\\neurotec-media-1.0.0.jar" + "!/"),
                    new URL("jar:file:" + "C:\\tomcat\\lib\\neurotec-media-processing-1.0.0.jar" + "!/")};
            cl = URLClassLoader.newInstance(urls);
            List<String> files = new ArrayList<String>();
            files.add("C:\\tomcat\\lib\\jna-1.0.0.jar");
            files.add("C:\\tomcat\\lib\\neurotec-core-1.0.0.jar");
            files.add("C:\\tomcat\\lib\\neurotec-devices-1.0.0.jar");
            files.add("C:\\tomcat\\lib\\neurotec-biometrics-1.0.0.jar");
            files.add("C:\\tomcat\\lib\\neurotec-biometrics-client-1.0.0.jar");
            files.add("C:\\tomcat\\lib\\neurotec-licensing-1.0.0.jar");
            files.add("C:\\tomcat\\lib\\neurotec-licensing-1.0.0.jar");
            files.add("C:\\tomcat\\lib\\neurotec-media-1.0.0.jar");
            files.add("C:\\tomcat\\lib\\neurotec-media-processing-1.0.0.jar");


            for (String jarFileString : files) {
                jarFile = new JarFile(jarFileString);
                Enumeration<JarEntry> e = jarFile.entries();
                while (e.hasMoreElements()) {
                    JarEntry je = e.nextElement();
                    if (je.isDirectory() || !je.getName().endsWith(".class")) {
                        continue;
                    }
                    // -6 because of .class
                    String className = je.getName().substring(0, je.getName().length() - 6);
                    className = className.replace('/', '.');
                    Class c = cl.loadClass(className);

                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }


    private FingerHelper() {
        LibraryManager.initLibraryPath();
        String path = System.getProperty("java.library.path");
        loadJars();
        try {
            Class nLicense = cl.loadClass("com.neurotec.licensing.NLicense");
            Method obtainComponents = nLicense.getMethod("obtainComponents", String.class, int.class, String.class);
            if (/*!NLicense.obtainComponents("/local", 5000, matching)*/ !(boolean)obtainComponents.invoke(null, "/local", 5000,matching) ||
                    /*!NLicense.obtainComponents("/local", 5000, fingerExtraction)*/ !(boolean)obtainComponents.invoke(null, "/local", 5000,fingerExtraction)) {
                System.err.println("Could not obtain licenses for components: " + matching);
            }


            biometricClient = (NBiometricClient) cl.loadClass("com.neurotec.biometrics.client.NBiometricClient").newInstance();//new NBiometricClient();

            //load subjects from database
            Map<String, byte[]> users = DatabaseHelper.getInstance().getUsersAndTemplate();
            for (Map.Entry<String, byte[]> entry : users.entrySet()) {
                addFingerToCache(entry.getKey(), entry.getValue());
            }

        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }  catch (SQLException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
    }

    public static FingerHelper getInstance(){
        if(instance == null)
            instance = new FingerHelper();
        return instance;
    }

    public void addFingerToCache(String user, byte[] template){
        NBuffer buffer = new NBuffer(template);
        NSubject subject = NSubject.fromMemory(buffer);
        subject.setId(user);
        subjects.add(subject);
        //biometricClient.createTemplate(subject); ??
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

