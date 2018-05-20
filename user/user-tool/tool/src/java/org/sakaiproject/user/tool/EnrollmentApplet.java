package org.sakaiproject.user.tool;

import com.neurotec.biometrics.*;
import com.neurotec.biometrics.client.NBiometricClient;
import com.neurotec.devices.NDeviceManager;
import com.neurotec.devices.NDeviceType;
import com.neurotec.devices.NFScanner;
import com.neurotec.licensing.NLicense;
import netscape.javascript.JSObject;
import org.sakaiproject.util.RSAHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
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
import java.util.List;

public class EnrollmentApplet extends Applet{

    private Image image;
    private Label scannerStatus = new Label();
    private TextField user = new TextField(100);
    private Button submit = new Button("Submit");
    private Button scan = new Button("Scan");
    final String fingerScanner = "Devices.FingerScanners";
    final String fingerExtraction = "Biometrics.FingerExtraction";
    NDeviceManager deviceManager;
    NFScanner scanner;
    NFinger finger;
    NSubject subject;
    NBiometricClient biometricClient = new NBiometricClient();
    private Label enrollStatus = new Label();
    private Label username = new Label("Username: ");
    private Label password = new Label("Password: ");
    private TextField pw = new TextField(100);
    private Label info1 = new Label("*By adding your credentials and fingerprint you agree to the processing");
    private Label info2 = new Label("and storing of your private information.");

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
        scannerStatus.setText("Searching for scanner... Please wait.");

        // enrollStatus
        add(enrollStatus);
        enrollStatus.setBounds(40,110,400,20);

        // info1
        add(info1);
        info1.setBounds(40, 130, 400, 20);
        info1.setForeground(Color.red);

        // info2
        add(info2);
        info2.setBounds(40, 150, 400, 20);
        info2.setForeground(Color.red);

        // username
        add(username);
        username.setBounds(40, 60, 60, 20);

        // user
        add(user);
        user.setBounds(110,60,330,20);
        user.setBackground(Color.decode("#f2a2a2"));
        user.addTextListener(new TextListener() {
            @Override
            public void textValueChanged(TextEvent e) {
                if (user.getText().isEmpty())
                    user.setBackground(Color.decode("#f2a2a2"));
                else
                    user.setBackground(Color.decode("#c0edc2"));
            }
        });

        // scan
        scan.setBounds(450,30,50,20);
        add(scan);
        scan.addActionListener(e->{
            scanFinger();
        });
        scan.setEnabled(false);

        // password
        add(password);
        password.setBounds(40, 80, 60, 20);

        // pw
        add(pw);
        pw.setBounds(110,80,330,20);
        pw.setBackground(Color.decode("#f2a2a2"));
        pw.setEchoChar('*');
        pw.addTextListener(new TextListener() {
            @Override
            public void textValueChanged(TextEvent e) {
                if (pw.getText().isEmpty())
                    pw.setBackground(Color.decode("#f2a2a2"));
                else
                    pw.setBackground(Color.decode("#c0edc2"));
            }
        });

        // submit
        add(submit);
        submit.setBounds(450,80,50,20);
        submit.addActionListener(e -> {
            if(finger == null){
                enrollStatus.setText("Please scan finger!");
                enrollStatus.setForeground(Color.red);
            } else if(user.getText().isEmpty()){
                enrollStatus.setText("Please add username and press submit.");
                enrollStatus.setForeground(Color.red);
            } else if(pw.getText().isEmpty()){
                enrollStatus.setText("Please add password and press submit.");
                enrollStatus.setForeground(Color.red);
            } else
                sendTemplateToServer();
        });
    }

    public void initVerifingerSDK(){
        LibraryManager.initLibraryPath();
        try {
            if (!NLicense.obtainComponents("/local", 5000, fingerScanner) ||
                    !NLicense.obtainComponents("/local", 5000, fingerExtraction)) {
                System.err.println("Could not obtain licenses for components: " + fingerScanner + ", " + fingerExtraction);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void scanFinger(){
        reset();
        scan.setEnabled(false);
        finger = new NFinger();
        subject = new NSubject();
        subject.getFingers().add(finger);
        finger.setCaptureOptions(EnumSet.of(NBiometricCaptureOption.MANUAL));
        finger.setPosition(NFPosition.UNKNOWN);
        scanner.capture(finger, -1);

        image = finger.getImage().toImage();
        image = image.getScaledInstance(70,90,Image.SCALE_SMOOTH);
        scan.setEnabled(true);
        this.repaint();
        String status = "Fingerprint acquired.";
        if(user.getText().isEmpty())
            status += "Please add username and submit!";
        else
            status += "You can submit!";
        enrollStatus.setText(status);
        enrollStatus.setForeground(Color.decode("#0c9307"));
    }

    public String getCookies() {
        System.out.println("Get cookies");
        String cookie = (String)document.getMember("cookie");
        System.out.println("Cookies: " + cookie);
        return cookie;
    }

    public void sendTemplateToServer(){
        try {
            URL url = new URL(getCodeBase(), "/portal/enrollment");
            System.out.println(url.getPath());
            URLConnection con = url.openConnection();
            if (con instanceof HttpURLConnection) {
                ((HttpURLConnection)con).setRequestMethod("POST");
            }
            con.setDoOutput(true);
            con.setUseCaches(false);
            con.setRequestProperty("Content-Type", "application/octet-stream");
            con.setRequestProperty("user",user.getText());
            con.setRequestProperty("pw",pw.getText());
            con.setRequestProperty("Cookie", getCookies());

            biometricClient.createTemplate(subject);
            byte[] template = subject.getTemplateBuffer().toByteArray();

            URL urlCert = new URL("http://localhost:8080/res/ISMCertificateX509.cer");
            URLConnection conCert = urlCert.openConnection();
            PublicKey publicKey = RSAHelper.getCertificateKey(conCert.getInputStream());

            byte[] cipherText = RSAHelper.encrypt(template, publicKey);
            con.setRequestProperty("size", String.valueOf(template.length));

            BufferedOutputStream out = new BufferedOutputStream(con.getOutputStream());

            out.write(cipherText,0,cipherText.length);
            out.flush();
            out.close();

            enrollStatus.setText("Successfully enrolled!");
            enrollStatus.setForeground(Color.decode("#0c9307"));
            BufferedReader in = new BufferedReader( new InputStreamReader(con.getInputStream()));
            String decodedString;
            if ((decodedString = in.readLine()) != null) {
                enrollStatus.setText(decodedString);
                enrollStatus.setForeground(Color.RED);
            }
        } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException |CertificateException e1) {
            e1.printStackTrace();
            enrollStatus.setText("Error while enrolling!");
            enrollStatus.setForeground(Color.red);
        }
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

    void reset(){
        enrollStatus.setText("");
        image = null;
        this.repaint();
    }

}

