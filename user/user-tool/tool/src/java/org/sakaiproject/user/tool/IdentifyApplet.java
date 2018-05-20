package org.sakaiproject.user.tool;

import com.neurotec.biometrics.*;
import com.neurotec.biometrics.client.NBiometricClient;
import com.neurotec.devices.NDeviceManager;
import com.neurotec.devices.NDeviceType;
import com.neurotec.devices.NFScanner;
import com.neurotec.io.NBuffer;
import com.neurotec.licensing.NLicense;
import netscape.javascript.JSObject;
import org.sakaiproject.util.RSAHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.applet.Applet;
import java.awt.*;
import java.awt.event.TextEvent;
import java.awt.event.TextListener;
import java.io.*;
import java.net.*;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.EnumSet;

public class IdentifyApplet extends Applet {
    private Image image;
    private Label scannerStatus = new Label();
    private TextField user = new TextField(100);
    private Button identify = new Button("Identify");
    private Button scan = new Button("Scan");
    final String fingerScanner = "Devices.FingerScanners";
    final String fingerExtraction = "Biometrics.FingerExtraction";
    final String matching = "Biometrics.FingerMatching";
    NDeviceManager deviceManager;
    NFScanner scanner;
    NFinger finger;
    NSubject subjectToIdentify;
    NBiometricClient biometricClient = new NBiometricClient();
    private Label username = new Label("Username: ");
    private Label identifyStatus = new Label();

    private JSObject window;
    private JSObject document;

    public void init(){
        initLayout();
        initVerifingerSDK();

        window = JSObject.getWindow(this);
        document = (JSObject) window.getMember("document");
    }

    public void initLayout(){
        setLayout(null);

        // scannerStatus
        add(scannerStatus);
        scannerStatus.setBounds(40,30,400,20);
        scannerStatus.setText("Searching for scanner...");

        // identifyStatus
        add(identifyStatus);
        identifyStatus.setBounds(40,90,400,20);

        // username
        add(username);
        username.setBounds(40, 60, 60, 20);

        // user
        add(user);
        user.setBounds(110,60,330,20);
        user.setBackground(Color.decode("#f2a2a2"));
        user.setText("Press to identify...");
        user.setEnabled(false);

        // scan
        scan.setBounds(450,30,50,20);
        add(scan);
        scan.addActionListener(e->{
            scanFinger();
        });
        scan.setEnabled(false);

        // identify
        add(identify);
        identify.setBounds(450,60,50,20);
        identify.addActionListener(e -> {
            identifyUser();
        });
    }

    public void initVerifingerSDK(){
        LibraryManager.initLibraryPath();
        try {
            if (!NLicense.obtainComponents("/local", 5000, fingerScanner) ||
                    !NLicense.obtainComponents("/local", 5000, fingerExtraction) ||
                    !NLicense.obtainComponents("/local", 5000,matching)) {
                System.err.println("Could not obtain licenses for components: " + fingerScanner + ", " + fingerExtraction + ", "+ matching);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void scanFinger(){
        reset();
        scan.setEnabled(false);
        finger = new NFinger();
        subjectToIdentify = new NSubject();
        subjectToIdentify.getFingers().add(finger);
        finger.setCaptureOptions(EnumSet.of(NBiometricCaptureOption.MANUAL));
        finger.setPosition(NFPosition.UNKNOWN);
        scanner.capture(finger, -1);

        image = finger.getImage().toImage();
        image = image.getScaledInstance(70,90,Image.SCALE_SMOOTH);
        scan.setEnabled(true);
        this.repaint();
    }

    public String getCookies() {
        System.out.println("Get cookies");
        String cookie = (String)document.getMember("cookie");
        System.out.println("Cookies: " + cookie);
        return cookie;
    }

    public void identifyUser(){
        if(finger == null){
            identifyStatus.setText("Please scan finger and press identify.");
            identifyStatus.setForeground(Color.red);
            return;
        }

        try {
            URL url = new URL(getCodeBase(), "/portal/identify");
            URLConnection con = url.openConnection();
            if (con instanceof HttpURLConnection) {
                ((HttpURLConnection)con).setRequestMethod("GET");
            }
            con.setDoOutput(true);
            con.setUseCaches(false);
            con.setRequestProperty("Content-Type", "application/octet-stream");
            con.setRequestProperty("user",user.getText());
            con.setRequestProperty("Cookie", getCookies());

            biometricClient.createTemplate(subjectToIdentify);
            byte[] template = subjectToIdentify.getTemplateBuffer().toByteArray();

            URL urlCert = new URL("http://localhost:8080/res/ISMCertificateX509.cer");
            URLConnection conCert = urlCert.openConnection();
            PublicKey publicKey = RSAHelper.getCertificateKey(conCert.getInputStream());
            byte[] cipherText = RSAHelper.encrypt(template, publicKey);
            con.setRequestProperty("size", String.valueOf(template.length));

            BufferedOutputStream out = new BufferedOutputStream(con.getOutputStream());

            out.write(cipherText,0,cipherText.length);
            out.flush();
            out.close();

            BufferedReader in = new BufferedReader( new InputStreamReader(con.getInputStream()));
            String decodedString;
            boolean found = false;
            if ((decodedString = in.readLine()) != null) {
                user.setText(decodedString);
                found = true;
            }
            in.close();

            if(found) {
                String message = "User authenticated. Please use the following code to connect: " + getCode(user.getText());
                identifyStatus.setText(message);
                identifyStatus.setForeground(Color.decode("#0c9307"));
            }else{
                identifyStatus.setText("User not found. Please try again.");
                identifyStatus.setForeground(Color.red);
            }
        } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e1) {
            e1.printStackTrace();
        }
    }

    String getCode(String user) throws IOException {
        URL url = new URL(getCodeBase(), "/portal/generateCode");
        URLConnection con = url.openConnection();
        if (con instanceof HttpURLConnection) {
            ((HttpURLConnection)con).setRequestMethod("GET");
        }
        con.setDoOutput(true);
        con.setUseCaches(false);
        con.setRequestProperty("Content-Type", "application/octet-stream");
        con.setRequestProperty("Cookie", getCookies());

        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(con.getOutputStream()));
        writer.write(user);
        writer.flush();
        writer.close();

        BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String code = reader.readLine();
        reader.close();

        return code;
    }

    void reset(){
        user.setText("Press to identify...");
        identifyStatus.setText("");
        image = null;
        this.repaint();
    }

    public void start(){
        deviceManager = new NDeviceManager();
        deviceManager.setDeviceTypes(EnumSet.of(NDeviceType.FINGER_SCANNER));
        deviceManager.setAutoPlug(true);
        deviceManager.initialize();
        scanner = (NFScanner)deviceManager.getDevices().get(0);
        scannerStatus.setText("Found scanner: " + scanner.getDisplayName()+ "!") ;
        scan.setEnabled(true);
    }

    public void paint(Graphics g){
        if(image != null)
            g.drawImage(image,520,30,this);
    }

}