package gov.gsa.icamcardbuilder.app;

import org.apache.logging.log4j.LogManager;

import javax.swing.JTextArea;
import javax.swing.JProgressBar;
import java.io.File;
import java.io.FileInputStream;
import java.util.Hashtable;
import java.util.Properties;

// this was used to regenerate the expired CHUID test card's Security Object without GUI dependencies, 
// but it can be used to sign any card content in headless mode (e.g. on a build server) by passing a properties file as an argument

public class HeadlessSigner {
    public static void main(String[] args) throws Exception {
        System.setProperty("java.awt.headless", "true");

        // Initialize the static Gui fields that ContentSignerTool writes to.
        // JTextArea and JProgressBar modify their data models only (no painting),
        // so construction succeeds in headless mode on Java 11+.
        Gui.logger   = LogManager.getLogger("HeadlessSigner");
        Gui.status   = new JTextArea();
        Gui.progress = new JProgressBar();
        Gui.errors   = false;
        Gui.checkRevocation = false;   // skip OCSP/CRL network call

        Properties prop = new Properties();
        String propsPath = args.length > 0 ? args[0]
            : "cards/ICAM_Card_Objects/11_Certs_Expire_after_CHUID/c11-chuid.properties";
        prop.load(new FileInputStream(propsPath));

        Hashtable<String, String> properties = new Hashtable<>();
        for (String key : prop.stringPropertyNames()) {
            properties.put(key, prop.getProperty(key).trim());
        }
        // uuid must have dashes stripped (mirrors Gui.processProperties behaviour)
        if (properties.containsKey("uuid"))
            properties.put("uuid", properties.get("uuid").replace("-", ""));
        if (properties.containsKey("cardholderUuid"))
            properties.put("cardholderUuid",
                properties.get("cardholderUuid").replace("-", ""));

        // Supply defaults for optional properties that Gui normally injects
        // (see Gui.createSigningWorker().putProperties())
        properties.putIfAbsent("pivCardApplicationAid", "");
        properties.putIfAbsent("pinUsagePolicy", "");
        properties.putIfAbsent("name", "");
        properties.putIfAbsent("employeeAffiliation", "");
        properties.putIfAbsent("agencyCardSerialNumber", "1234567890");

        File contentFile = new File(properties.get("contentFile"));
        File secObjectFile = new File(properties.get("securityObjectFile"));

        System.out.println("Signing: " + contentFile);
        System.out.println("Security Object: " + secObjectFile);

        // initSo=false: preserve existing Security Object DG hashes for other containers
        new ContentSignerTool(contentFile, secObjectFile, properties, false);

        if (Gui.errors) {
            System.err.println("Signing failed -- check log output above.");
            System.exit(1);
        }
        System.out.println("Done. Errors: " + Gui.errors);
    }
}
