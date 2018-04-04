package org.sakaiproject.user.tool;

import com.neurotec.biometrics.*;
import com.neurotec.biometrics.client.NBiometricClient;
import com.neurotec.devices.NDeviceManager;
import com.neurotec.devices.NDeviceType;
import com.neurotec.devices.NFScanner;
import com.neurotec.io.NBuffer;
import com.neurotec.licensing.NLicense;

import java.applet.Applet;
import java.awt.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.EnumSet;

public class IdentifyApplet extends Applet {
    private Image image;
    private Label resultField = new Label();
    private TextField user = new TextField(100);
    private Button identify = new Button("Identify");
    private Button scan = new Button("Scan");
    final String components = "Devices.FingerScanners";
    final String fingerExtraction = "Biometrics.FingerExtraction";
    final String matching = "Biometrics.FingerMatching";
    NDeviceManager deviceManager;
    NFScanner scanner;
    NFinger finger;
    NSubject subjectToIdentify;
    NBiometricClient biometricClient = new NBiometricClient();
    private Label username = new Label("Username: ");
    private Label label = new Label();

    public void init(){
        initLayout();
        initVerifingerSDK();
    }

    public void initLayout(){
        setLayout(null);
        add(resultField);
        resultField.setBounds(40,30,400,20);
        resultField.setText("Searching for scanner...");
        add(label);
        label.setBounds(40,90,400,20);
        add(username);
        username.setBounds(40, 60, 60, 20);
        add(user);
        user.setBounds(110,60,330,20);
        scan.setBounds(450,30,50,20);
        add(scan);
        scan.addActionListener(e->{
            scanFinger();
        });
        add(identify);
        identify.setBounds(450,60,50,20);
        identify.addActionListener(e -> {
            identifyUser();
        });
    }

    public void initVerifingerSDK(){
        LibraryManager.initLibraryPath();
        try {
            if (!NLicense.obtainComponents("/local", 5000, components) ||
                    !NLicense.obtainComponents("/local", 5000, fingerExtraction) ||
                    !NLicense.obtainComponents("/local", 5000,matching)) {
                System.err.println("Could not obtain licenses for components: " + components);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void scanFinger(){
        scan.setEnabled(false);
        finger = new NFinger();
        subjectToIdentify = new NSubject();
        subjectToIdentify.getFingers().add(finger);
        finger.setCaptureOptions(EnumSet.of(NBiometricCaptureOption.MANUAL));
        finger.setPosition(NFPosition.UNKNOWN);
        NBiometricStatus status = scanner.capture(finger, -1);
        if (status != NBiometricStatus.OK) {
            System.err.format("failed to capture from scanner, status: %s%n", status);
        }
        image = finger.getImage().toImage();
        image = image.getScaledInstance(70,90,Image.SCALE_SMOOTH);
        scan.setEnabled(true);
        this.repaint();
    }

    public void identifyUser(){
        if(user.getText().equals("")){
            label.setText("Please add username and press submit.");
            label.setForeground(Color.red);
            return;
        }else if(finger == null){
            label.setText("Please add username and press submit.");
            label.setForeground(Color.red);
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
            subjectToIdentify.setId(user.getText());


            BufferedInputStream reader = new BufferedInputStream(con.getInputStream());
            byte[] buff = new byte[1000];
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            int bytesRead = 0;
            while ((bytesRead = reader.read(buff)) != -1)
                output.write(buff,0,bytesRead);
            byte[] template = output.toByteArray();
            int size = template.length;

            NBuffer buffer = new NBuffer(template);
            NSubject subject = NSubject.fromMemory(buffer);
            subject.setId(user.getText());
            biometricClient.enroll(subject);
            biometricClient.identify(subjectToIdentify);

            boolean found = false;
            for (NMatchingResult result : subjectToIdentify.getMatchingResults()) {
                if (subjectToIdentify.getId().equals(result.getId())) {
                    found = true;
                    break;
                }
            }

            if(found){
                label.setText("User authenticated. Please use the following code to connect: ");
                label.setForeground(Color.green);
            }else{
                label.setText("User not authenticated. Please try again.");
                label.setForeground(Color.red);
            }
            //if match request to generate a code

        } catch (MalformedURLException e1) {
            e1.printStackTrace();
        } catch (IOException e1) {
            e1.printStackTrace();
        }
    }

    public void start(){
        deviceManager = new NDeviceManager();
        deviceManager.setDeviceTypes(EnumSet.of(NDeviceType.FINGER_SCANNER));
        deviceManager.setAutoPlug(true);
        deviceManager.initialize();
        scanner = (NFScanner)deviceManager.getDevices().get(0);
        resultField.setText("Found scanner: " + scanner.getDisplayName()+ "!") ;
    }

    public void paint(Graphics g){
        if(image != null)
            g.drawImage(image,520,30,this);
    }

}