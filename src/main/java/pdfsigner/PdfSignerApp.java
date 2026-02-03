package pdfsigner;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attribute; // <— WICHTIG
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SimpleAttributeTableGenerator; 
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TSPAlgorithms;

import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.builder.api.AppenderComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;
import org.apache.logging.log4j.core.Filter;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * PdfSignerApp (komplett):
 *   - Verwendung eines einzigen PKCS#11-Keystores (USB-Token / AATL) fuer alle Firmen
 *   - Dynamische Signatur-Parameter (Name, Reason, Location) je nach Ziel-Firma
     *   - slotListIndex kommt aus config.properties (oder wird automatisch gescannt)
 *   - TSA-URL wird aus der AIA-Erweiterung im Zertifikat ausgelesen
 */
public class PdfSignerApp {
    private static final Logger logger = LogManager.getLogger(PdfSignerApp.class);
    private static final String NTP_SERVER = "DC-00-MEU.meurer.local";

    // PKCS#11-Provider und KeyStore
    private static Provider pkcs11Provider;
    private static KeyStore pkcs11KeyStore;

    public static void main(String[] args) {
        final Config cfg;

        try {
            // Konfiguration einlesen (inkl. pkcs11.slot)
            cfg = loadConfig();
        } catch (Exception e) {
            System.err.println("Fehler in Konfiguration: " + e.getMessage());
            logger.error("Fehler beim Laden der Konfiguration", e);
            System.exit(99);
            return;
        }

        try {
            setupLogging(cfg.logPath);
        } catch (IOException e) {
            System.err.println("Fehler beim Setzen des Loggings: " + e.getMessage());
            System.exit(99);
        }
        
        try {
            // PKCS#11 Provider initialisieren (mit slotIndex oder auto-scan)
            initPKCS11(cfg.pkcs11LibraryPath, cfg.pkcs11Slot, cfg.pkcs11SlotScanMax, cfg.pkcs11Pin);
        } catch (Exception e) {
            System.err.println("Fehler in Token-Initialisierung: " + e.getMessage());
            logger.error("Fehler bei der PKCS#11-Initialisierung", e);
            System.exit(99);
            return;
        }

        try (Scanner scanner = new Scanner(System.in)) {
            LocalDate filterDate = readFilterDate(scanner);
            // setupLogging(cfg.logPath);
            Set<String> exceptionCustomers = loadExceptions();
            processFilteredFiles(cfg, filterDate, exceptionCustomers);
        } catch (Exception e) {
            logger.error("Fehler beim Verarbeiten: ", e);
            System.err.println("Fehler: " + e.getMessage());
            System.exit(99);
        }
    }

    /**
     * Liest Datum im Format TT.MM.JJJJ ein.
     */
    private static LocalDate readFilterDate(Scanner scanner) {
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("dd.MM.yyyy");
        LocalDate date = null;
        while (date == null) {
            System.out.print("Bitte Datum eingeben (TT.MM.JJJJ): ");
            String input = scanner.nextLine().trim();
            try {
                date = LocalDate.parse(input, fmt);
            } catch (Exception e) {
                System.out.println("Ungueltiges Datum. Bitte erneut eingeben.");
            }
        }
        return date;
    }

    /**
     * Verarbeitet alle PDF-Dateien, deren letztes aenderungsdatum = filterDate ist:
     *   - Verschiebt in Backup-Ordner
     *   - Verschluesselt
     *   - Signiert (PKCS#11)
     *   - Speichert Ergebnis zurueck in Source-Ordner
     */
    private static void processFilteredFiles(Config cfg, LocalDate filterDate, Set<String> exceptionCustomers) throws IOException {
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("dd.MM.yyyy");
        String dateStr = filterDate.format(fmt);

        List<Path> files = Files.list(Paths.get(cfg.sourceDir))
                .filter(p -> p.toString().toLowerCase().endsWith(".pdf"))
                .filter(p -> {
                    try {
                        FileTime ft = Files.getLastModifiedTime(p);
                        LocalDate fileDate = ft.toInstant()
                                .atZone(ZoneId.systemDefault())
                                .toLocalDate();
                        return fileDate.equals(filterDate);
                    } catch (IOException e) {
                        logger.warn("Kann Aenderungsdatum nicht lesen: {}", p, e);
                        return false;
                    }
                })
                .collect(Collectors.toList());

        int total = files.size();
        if (total == 0) {
            System.out.println("Keine PDF-Dateien mit Datum " + dateStr + " im Quellverzeichnis gefunden.");
            return;
        }

        try (Scanner scanner = new Scanner(System.in)) {
            System.out.printf("Sind Sie sicher, dass Sie %d Dateien vom %s signieren moechten (J/N)? ", total, dateStr);
            String confirm = scanner.nextLine().trim();
            if (!confirm.equalsIgnoreCase("J")) {
                System.out.println("Abgebrochen.");
                return;
            }
            logger.info("Start Signatur der Dateien vom " + dateStr);
        }

        int processed = 0;
        int backedUpCount = 0;
        int signedCount = 0;
        int skippedCount = 0;
        int failedCount = 0;

        for (Path file : files) {
            processed++;
            // Statusmeldung (nur Konsole)
            System.out.printf("\rVerarbeite %d/%d Dateien (%.1f%%)", processed, total, processed * 100.0 / total);

            
            // Ausnahmen (Kunden, die nicht verarbeitet werden sollen)
            Optional<String> maybeCustomer = extractCustomerFromFileName(file.getFileName().toString());
            if (maybeCustomer.isPresent() && exceptionCustomers.contains(maybeCustomer.get())) {
                String msg = String.format("Datei '%s' gehoert zu Ausnahme-Kundennr. %s und wird uebersprungen.",
                        file.getFileName(), maybeCustomer.get());
                System.out.println("\n" + msg);
                logger.warn(msg);
                skippedCount++;
                continue;
            }

            try (PDDocument checkDoc = Loader.loadPDF(file.toFile())) {
                // Wenn bereits signiert, ueberspringen
                if (!checkDoc.getSignatureDictionaries().isEmpty()) {
                    String msg = String.format("Datei '%s' ist bereits signiert und wird uebersprungen.", file.getFileName());
                    System.out.println("\n" + msg);
                    logger.warn(msg);
                    skippedCount++;
                    continue; // Naechste Datei
                }
            } catch (IOException e) {
                // Falls PDF nicht geladen werden kann, als Fehler zaehlen und naechste Datei
                String msg = String.format("Kann PDF nicht oeffnen zur Signatur-Pruefung: %s", file.getFileName());
                System.err.println("\n" + msg);
                logger.error(msg, e);
                failedCount++;
                continue;
            }

            try {
                // 1) Backup: Datei verschieben
                Path backupPath = Paths.get(cfg.backupDir, file.getFileName().toString());
                Files.move(file, backupPath);
                backedUpCount++;

                // 2) Verschluesseln
                String encryptedPath = encrypt(backupPath);

                // 3) Signieren (PKCS#11)
                String signedPath = signPdf(encryptedPath, file.getFileName().toString(), cfg);

                // 4) Zurueckverschieben des signierten Dokuments in das Quellverzeichnis
                Files.move(Paths.get(signedPath), file);

                // 5) Aufraeumen temporaerer Dateien
                cleanupTemp(encryptedPath, signedPath);

                String okMsg = String.format("Erfolg: %s", file.getFileName());
                logger.info(okMsg);
                signedCount++;
            } catch (Exception e) {
                failedCount++;
                logger.error("Fehler mit Datei {}: ", file.getFileName(), e);
            }
        }

        System.out.println();

        System.out.println("--- Zusammenfassung ---");
        System.out.println("Gesicherte Dateien    : " + backedUpCount);
        System.out.println("Erfolgreiche Signaturen: " + signedCount);
        System.out.println("Uebersprungene Dateien : " + skippedCount);
        System.out.println("Fehlgeschlagene Vorgaenge: " + failedCount);

        logger.info("--- Zusammenfassung ---");
        logger.info("Gesicherte Dateien    : {}", backedUpCount);
        logger.info("Erfolgreiche Signaturen: {}", signedCount);
        logger.info("Uebersprungene Dateien : {}", skippedCount);
        logger.info("Fehlgeschlagene Vorgaenge: {}", failedCount);
    }

    /**
     * Laedt die Konfiguration aus config.properties.
     * Neue Felder: pkcs11.library, pkcs11.slot, pkcs11.slot.scan.max, pkcs11.pin
     */
    private static Config loadConfig() throws IOException {
        File configFile = new File("config.properties");
        if (!configFile.isFile()) {
            throw new IOException("Konfigurationsdatei 'config.properties' nicht gefunden.");
        }
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configFile)) {
            props.load(fis);
        }
        return new Config(props);
    }

    /**
     * Initialisiert den PKCS#11-Provider (SunPKCS11) anhand der Bibliotheks-Pfades, Slot-Index und PIN.
     * Der Slot-Index wird nun aus der Config uebergeben.
     */
    private static void initPKCS11(String pkcs11LibraryPath, Integer slotIndex, int slotScanMax, char[] pin) throws Exception {
        if (slotIndex != null) {
            initPKCS11ForSlot(pkcs11LibraryPath, slotIndex, pin);
            return;
        }

        List<Exception> errors = new ArrayList<>();
        for (int idx = 0; idx <= slotScanMax; idx++) {
            try {
                initPKCS11ForSlot(pkcs11LibraryPath, idx, pin);
                if (pkcs11KeyStore.size() > 0) {
                    logger.info("PKCS#11 Slot automatisch gefunden: slotListIndex={}", idx);
                    return;
                }
                logger.warn("PKCS#11 Slot {} hat keine Aliase, naechster Slot wird getestet.", idx);
                cleanupPkcs11Provider();
            } catch (Exception e) {
                errors.add(e);
                logger.debug("PKCS#11 Slot {} konnte nicht geladen werden: {}", idx, e.getMessage());
                cleanupPkcs11Provider();
            }
        }

        throw new Exception("Kein passender PKCS#11 Slot gefunden (0-" + slotScanMax + ").");
    }

    private static void initPKCS11ForSlot(String pkcs11LibraryPath, int slotIndex, char[] pin) throws Exception {
        // -------------------------------
        // 1) Baue den Inhalt der PKCS#11-Konfigurationsdatei (mit dynamischem slotListIndex)
        // -------------------------------
        String pkcs11ConfigText =
                "name = USBToken\n" +
                "library = " + pkcs11LibraryPath + "\n" +
                "slotListIndex = " + slotIndex + "\n";

        // -------------------------------
        // 2) Schreibe den Text in eine temporaere Datei
        // -------------------------------
        File tempConfig = File.createTempFile("pkcs11-", ".cfg");
        tempConfig.deleteOnExit(); // loescht die Datei beim Beenden der JVM

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(tempConfig))) {
            writer.write(pkcs11ConfigText);
            writer.flush();
        } catch (IOException ioe) {
            throw new IOException("Fehler beim Schreiben der PKCS#11-Konfigurationsdatei: " + ioe.getMessage(), ioe);
        }

        // -------------------------------
        // 3) Hole den unkonfigurierten SunPKCS11-Provider und konfiguriere ihn
        // -------------------------------
        Provider baseProv = Security.getProvider("SunPKCS11");
        if (baseProv == null) {
            throw new Exception("SunPKCS11-Provider nicht gefunden. Stellen Sie sicher, dass Ihr JDK mit PKCS#11-Unterstuetzung ausgeliefert wurde.");
        }

        // Konfiguriere den Provider ueber die temporaere .cfg-Datei
        Provider p11 = baseProv.configure(tempConfig.getAbsolutePath());
        // Registriere den konfigurierten Provider (Name z. B. "SunPKCS11-USBToken")
        Security.addProvider(p11);
        pkcs11Provider = p11;

        // -------------------------------
        // 4) (Optional) Debug: Liste alle Provider und ihre KeyStore-Algorithmen auf
        //    Damit siehst du, ob "PKCS11" wirklich registriert wurde
        // -------------------------------
        logger.info("---- Installierte Provider und ihre KeyStore-Algorithmen ----");
        for (Provider prov : Security.getProviders()) {
            logger.info("** Provider: {}", prov.getName());
            prov.getServices().stream()
                    .filter(svc -> "KeyStore".equals(svc.getType()))
                    .forEach(svc -> logger.info("   KeyStore-Algorithmus: {}", svc.getAlgorithm()));
        }
        logger.info("---------------------------------------------------------------");


        // -------------------------------
        // 5) KeyStore per Typ "PKCS11" laden (ohne expliziten Provider-Parameter)
        //    Java verwendet automatisch den registrierten PKCS#11-Provider.
        // -------------------------------
        pkcs11KeyStore = KeyStore.getInstance("PKCS11");
        pkcs11KeyStore.load(null, pin);

        // (Optional) Zeige Aliase auf dem Token
        System.out.println("Aliase auf dem Token:");
        Enumeration<String> aliases = pkcs11KeyStore.aliases();
        while (aliases.hasMoreElements()) {
            System.out.println("  -> " + aliases.nextElement());
        }
    }

    private static void cleanupPkcs11Provider() {
        if (pkcs11Provider != null) {
            Security.removeProvider(pkcs11Provider.getName());
            pkcs11Provider = null;
        }
        pkcs11KeyStore = null;
    }

    /**
     * Konfiguriert Logging (Console ab WARN, File ab INFO wie zuvor).
     */
    private static void setupLogging(String logDir) throws IOException {
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        ctx.stop();

        ConfigurationBuilder<BuiltConfiguration> builder = ConfigurationBuilderFactory.newConfigurationBuilder();
        builder.setStatusLevel(Level.WARN);
        builder.setConfigurationName("PdfSignerConfig");

        // Console-Appender (WARN+)
        AppenderComponentBuilder console = builder.newAppender("Console", "Console")
                .addAttribute("target", "SYSTEM_OUT");
        console.add(builder.newLayout("PatternLayout")
                .addAttribute("pattern", "%d{yyyy-MM-dd HH:mm:ss} %-5level %msg%n"));
        console.add(builder.newFilter("ThresholdFilter", Filter.Result.ACCEPT, Filter.Result.DENY)
                .addAttribute("level", "WARN"));
        builder.add(console);

        // File-Appender (INFO+)
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
        String fileName = Paths.get(logDir, ts + "-PdfSigner.log").toString();
        AppenderComponentBuilder file = builder.newAppender("File", "File")
                .addAttribute("fileName", fileName)
                .addAttribute("append", "false");
        file.add(builder.newLayout("PatternLayout")
                .addAttribute("pattern", "%d{yyyy-MM-dd HH:mm:ss} %-5level %msg%n"));
        file.add(builder.newFilter("ThresholdFilter", Filter.Result.ACCEPT, Filter.Result.DENY)
                .addAttribute("level", "INFO"));
        builder.add(file);

        // Root-Logger
        builder.add(builder.newRootLogger(Level.INFO)
                .add(builder.newAppenderRef("Console"))
                .add(builder.newAppenderRef("File")));

        BuiltConfiguration config = builder.build();
        ctx.start(config);
        ctx.updateLoggers();

        logger.info("Logging konfiguriert: Konsole=WARN+, Datei=INFO+");
    }

    /**
     * Verschluesselt das PDF (Standard PDFBox-Schutz).
     */
    private static String encrypt(Path pdfFile) throws IOException {
        String temp = pdfFile.toString().replace(".pdf", "[encrypted].pdf");
        try (PDDocument doc = Loader.loadPDF(pdfFile.toFile())) {
            AccessPermission ap = new AccessPermission();
            ap.setCanModify(false);
            ap.setCanModifyAnnotations(false);
            StandardProtectionPolicy spp = new StandardProtectionPolicy("passphrase", "", ap);
            spp.setEncryptionKeyLength(128);
            spp.setPreferAES(true);
            doc.protect(spp);
            doc.save(temp);
        }
        return temp;
    }

    /**
     * Signiert das verschluesselte PDF (PKCS#11-Token).
     */
    private static String signPdf(String encryptedPath, String originalFilename, Config cfg) throws Exception {
        // 1) Ermitteln, fuer welche Firma wir signieren (aus Dateiname)
        String issuer = getIssuerFromFileName(originalFilename);

        // 2) Signatur-Konfiguration holen (Name, Location, Reason)
        String prefix;
        if ("MEURER".equalsIgnoreCase(issuer) || "MEU".equalsIgnoreCase(issuer)) {
            prefix = "MEU";
        } else if ("MENOVA".equalsIgnoreCase(issuer) || "MEN".equalsIgnoreCase(issuer)) {
            prefix = "MEN";
        } else if ("SOVEM".equalsIgnoreCase(issuer) || "SOV".equalsIgnoreCase(issuer)) {
            prefix = "SOV";
        } else {
            prefix = "MEU"; // Default
            logger.warn("Unbekannter Aussteller '{}', verwende MEU als Default", issuer);
        }
        SigConfig sc = cfg.sigConfigs.get(prefix);

        // 3) PrivateKey und Zertifikatskette vom Token abrufen
        Enumeration<String> aliases = pkcs11KeyStore.aliases();
        if (!aliases.hasMoreElements()) {
            throw new Exception("Keine Schluessel auf dem PKCS#11-Token gefunden.");
        }
        String alias = aliases.nextElement(); // falls mehrere, ggf. anpassen
        PrivateKey key = (PrivateKey) pkcs11KeyStore.getKey(alias, null);
        Certificate[] chain = pkcs11KeyStore.getCertificateChain(alias);

        // 4) PDF laden und signieren
        Path encPath = Paths.get(encryptedPath);
        String signed = encryptedPath.replace("[encrypted].pdf", "[signed].pdf");
        try (PDDocument doc = Loader.loadPDF(encPath.toFile())) {
            if (!doc.getSignatureDictionaries().isEmpty()) {
                logger.warn("Datei bereits signiert: {}", encryptedPath);
                return encryptedPath;
            }
            PDSignature sig = new PDSignature();
            sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

            // Dynamisch: Name immer TH. MEURER AG, Reason & Location aus sc
            sig.setName(sc.name);
            sig.setLocation(sc.location);
            sig.setReason(sc.reason);
            sig.setSignDate(fetchNetworkTime());

            // Document MDP Transform Params (wie zuvor)
            PDDocumentCatalog catalog = doc.getDocumentCatalog();
            COSDictionary cd = catalog.getCOSObject();
            COSDictionary tfp = new COSDictionary();
            tfp.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
            tfp.setName(COSName.V, "1.2");
            tfp.setInt(COSName.P, 1);
            COSDictionary ref = new COSDictionary();
            ref.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
            ref.setItem(COSName.getPDFName("TransformMethod"), COSName.getPDFName("DocMDP"));
            ref.setItem(COSName.getPDFName("DigestMethod"), COSName.getPDFName("SHA1"));
            ref.setItem(COSName.getPDFName("TransformParams"), tfp);
            ref.setItem(COSName.getPDFName("Data"), cd);
            COSArray arr = new COSArray();
            arr.add(ref);
            sig.getCOSObject().setItem(COSName.getPDFName("Reference"), arr);
            COSDictionary perms = new COSDictionary();
            perms.setItem(COSName.getPDFName("DocMDP"), sig);
            cd.setItem(COSName.getPDFName("Perms"), perms);

            doc.addSignature(sig, new SignatureInterface() {
                @Override
                public byte[] sign(InputStream content) throws IOException {
                    try {
                        CMSTypedData msg = new InputStreamTypedData(content);
                        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(key);
                        gen.addSignerInfoGenerator(
                                new JcaSignerInfoGeneratorBuilder(
                                        new JcaDigestCalculatorProviderBuilder().build()
                                ).build(signer, (X509Certificate) chain[0])
                        );
                        gen.addCertificates(new JcaCertStore(Arrays.asList(chain)));

                        // Zeitstempel-Digest
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        byte[] hash = digest.digest(((InputStream) msg.getContent()).readAllBytes());

                        // TSA-Token holen (dynamisch aus Zertifikat)
                        TimeStampToken tst = fetchTimestampToken(hash, chain);
                        Attribute attr = new Attribute(
                                PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                                new DERSet(ASN1Primitive.fromByteArray(tst.getEncoded()))
                        );
                        gen.addSignerInfoGenerator(
                                new JcaSignerInfoGeneratorBuilder(
                                        new JcaDigestCalculatorProviderBuilder().build()
                                ).setUnsignedAttributeGenerator(
                                        new SimpleAttributeTableGenerator(new AttributeTable(attr))
                                ).build(signer, (X509Certificate) chain[0])
                        );

                        CMSSignedData signedData = gen.generate(msg, false);
                        return signedData.getEncoded();
                    } catch (Exception e) {
                        throw new IOException("Fehler beim Signieren: " + e.getMessage(), e);
                    }
                }
            });

            // 5) Unterschriftsbytes extern setzen
            try (FileOutputStream fos = new FileOutputStream(signed)) {
                ExternalSigningSupport ext = doc.saveIncrementalForExternalSigning(fos);
                byte[] sigBytes = sign(ext.getContent(), key, chain);
                ext.setSignature(sigBytes);
            }
        }
        return signed;
    }

    /**
     * Extrahiert das Aussteller-Token aus dem Dateinamen (gleich wie vorher).
     */
    private static String getIssuerFromFileName(String filename) {
        String[] parts = filename.split("_");
        if (parts.length >= 4 && parts[2].equalsIgnoreCase("NC")) {
            return parts[3];
        } else if (parts.length >= 3) {
            return parts[2];
        } else {
            return "";
        }
    }

    /**
     * Holt NTP-Zeit (wie zuvor).
     */
    private static Calendar fetchNetworkTime() {
        NTPUDPClient client = new NTPUDPClient();
        client.setDefaultTimeout(5000);
        try {
            TimeInfo info = client.getTime(InetAddress.getByName(NTP_SERVER));
            Date ntpDate = info.getMessage().getTransmitTimeStamp().getDate();
            Calendar cal = Calendar.getInstance();
            cal.setTime(ntpDate);
            return cal;
        } catch (IOException e) {
            logger.warn("Konnte NTP-Zeit nicht abrufen, verwende lokale Zeit", e);
            return Calendar.getInstance();
        } finally {
            client.close();
        }
    }

    /**
     * Erzeugt ein PKCS#7-Signaturobjekt aus den Inhalten plus Chain (fuer externe Signatur).
     */
    private static byte[] sign(InputStream content, PrivateKey key, Certificate[] chain) throws Exception {
        CMSTypedData msg = new InputStreamTypedData(content);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(key);
        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().build()
                ).build(cs, (X509Certificate) chain[0])
        );
        gen.addCertificates(new JcaCertStore(Arrays.asList(chain)));
        CMSSignedData signedData = gen.generate(msg, false);
        return signedData.getEncoded();
    }

    /**
     * Loescht temporaere Dateien.
     */
    private static void cleanupTemp(String enc, String signed) {
        try {
            Files.deleteIfExists(Paths.get(enc));
        } catch (Exception ignored) {
        }
        try {
            Files.deleteIfExists(Paths.get(signed));
        } catch (Exception ignored) {
        }
    }

    /**
     * Hilfsklasse fuer Signatur-Konfiguration (Name, Location, Reason).
     */
    private static class SigConfig {
        final String name;
        final String location;
        final String reason;

        SigConfig(String name, String location, String reason) {
            if (name == null || location == null || reason == null) {
                throw new IllegalArgumentException("Fehlende Signatur-Parameter in der Konfiguration");
            }
            this.name = name;
            this.location = location;
            this.reason = reason;
        }
    }

    /**
     * Konfigurationsklassen (liest aus Properties):
     *   - source.path, backup.path, log.path
     *   - pkcs11.library, pkcs11.slot, pkcs11.slot.scan.max, pkcs11.pin
     *   - sig.MEU.*, sig.MEN.*, sig.SOV.*
     */
    private static class Config {
        final String sourceDir;
        final String backupDir;
        final String logPath;
        final String pkcs11LibraryPath;
        final Integer pkcs11Slot;   // Slot-Index (null = auto)
        final int pkcs11SlotScanMax;
        final char[] pkcs11Pin;
        final Map<String, SigConfig> sigConfigs;

        Config(Properties config) throws IOException {
            this.sourceDir = requireDir(config, "source.path");
            this.backupDir = requireDir(config, "backup.path");
            this.logPath = requireString(config, "log.path");
            this.pkcs11LibraryPath = requireString(config, "pkcs11.library");
            this.pkcs11Slot = parseSlot(config, "pkcs11.slot");
            this.pkcs11SlotScanMax = requireIntOrDefault(config, "pkcs11.slot.scan.max", 10);
            this.pkcs11Pin = requireString(config, "pkcs11.pin").toCharArray();

            sigConfigs = new HashMap<>();
            sigConfigs.put("MEU", loadSigConfig(config, "MEU"));
            sigConfigs.put("MEN", loadSigConfig(config, "MEN"));
            sigConfigs.put("SOV", loadSigConfig(config, "SOV"));
        }

        private static SigConfig loadSigConfig(Properties cfg, String prefix) {
            return new SigConfig(
                    cfg.getProperty("sig." + prefix + ".name"),
                    cfg.getProperty("sig." + prefix + ".location"),
                    cfg.getProperty("sig." + prefix + ".reason")
            );
        }

        // Helfer-Methode, um eine String-Eigenschaft zu holen
        private static String requireString(Properties cfg, String key) throws IOException {
            String v = cfg.getProperty(key);
            if (v == null || v.isEmpty()) {
                throw new IOException("Fehlender Konfigurationswert: " + key);
            }
            return v;
        }

        // Helfer-Methode, um ein Verzeichnis zu validieren
        private static String requireDir(Properties cfg, String key) throws IOException {
            String path = requireString(cfg, key);
            File f = new File(path);
            if (!f.isDirectory()) {
                throw new IOException("Ungueltiges Verzeichnis fuer " + key + ": " + path);
            }
            return path;
        }

        // Helfer-Methode, um eine Integer-Eigenschaft zu holen
        //private static int requireInt(Properties cfg, String key) throws IOException {
        //    String val = requireString(cfg, key);
        //    try {
        //        return Integer.parseInt(val);
        //    } catch (NumberFormatException e) {
        //        throw new IOException("Ungueltiger Integer-Wert fuer " + key + ": " + val, e);
        //    }
        //}

        private static int requireIntOrDefault(Properties cfg, String key, int defaultValue) throws IOException {
            String val = cfg.getProperty(key);
            if (val == null || val.isEmpty()) {
                return defaultValue;
            }
            try {
                return Integer.parseInt(val);
            } catch (NumberFormatException e) {
                throw new IOException("Ungueltiger Integer-Wert fuer " + key + ": " + val, e);
            }
        }

        private static Integer parseSlot(Properties cfg, String key) throws IOException {
            String val = requireString(cfg, key).trim();
            if ("auto".equalsIgnoreCase(val)) {
                return null;
            }
            try {
                return Integer.parseInt(val);
            } catch (NumberFormatException e) {
                throw new IOException("Ungueltiger Slot-Wert fuer " + key + ": " + val + " (erwartet: Integer oder 'auto')", e);
            }
        }
    }

    /**
     * Liest aus dem uebergebenen X509Certificate die AIA-Erweiterung aus und sucht den
     * accessMethod id-ad-timeStamping. Gibt die zugehoerige URI als String zurueck,
     * oder null, falls keine TimeStamping-URL gefunden wurde.
     */
    private static String getTsaUrlFromCertificate(X509Certificate cert) throws IOException {
        byte[] aiaExtBytes = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aiaExtBytes == null) {
            return null;
        }

        // Die Extension ist in einem OCTET STRING verpackt
        ASN1Primitive derObj1 = ASN1Primitive.fromByteArray(aiaExtBytes);
        ASN1OctetString aiaOctets = (ASN1OctetString) derObj1;
        ASN1Primitive derObj2 = ASN1Primitive.fromByteArray(aiaOctets.getOctets());

        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(derObj2);
        AccessDescription[] descriptions = aia.getAccessDescriptions();
        for (AccessDescription ad : descriptions) {
           if (ad.getAccessMethod().equals(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.3"))) {
                GeneralName gn = ad.getAccessLocation();
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    return ((DERIA5String) gn.getName()).getString();
                }
            }
        }
        return null;
    }

    /**
     * Holt ein TimeStampToken vom TSA-Server, dessen URL in der AIA-Erweiterung
     * des (ersten) X509-Zertifikats in der chain[] steht.
     * @param hash  der Hash (z. B. SHA-256) ueber die zu stempelnden Daten
     * @param chain die X509-Zertifikatkette (Leaf-Zertifikat zuerst)
     */
    private static TimeStampToken fetchTimestampToken(byte[] hash, Certificate[] chain) throws Exception {
        if (chain == null || chain.length == 0) {
            throw new Exception("Keine Zertifikatskette uebergeben.");
        }
        X509Certificate leafCert = (X509Certificate) chain[0];
        String tsaUrl = getTsaUrlFromCertificate(leafCert);
        if (tsaUrl == null || tsaUrl.isEmpty()) {
            throw new Exception("Keine TSA-URL im Zertifikat (AIA extension) gefunden.");
        }

        // Erzeuge einen TimeStampRequest (SHA256)
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(true);
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        TimeStampRequest request = tsqGenerator.generate(TSPAlgorithms.SHA256, hash, nonce);

        byte[] reqData = request.getEncoded();

        // HTTP-Verbindung zum TSA-Server
        URL url = URI.create(tsaUrl).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/timestamp-query");
        conn.setRequestProperty("Content-Length", String.valueOf(reqData.length));

        try (OutputStream out = conn.getOutputStream()) {
            out.write(reqData);
            out.flush();
        }

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("TSA-Fehler: " + conn.getResponseCode() + " " + conn.getResponseMessage());
        }

        try (InputStream in = conn.getInputStream()) {
            TimeStampResponse response = new TimeStampResponse(in);
            response.validate(request);
            return response.getTimeStampToken();
        }
    }


    // Liest Kundennummern aus der Datei 'exceptions.txt' (eine Nummer pro Zeile).
    // Leere Zeilen und solche mit '#' am Anfang werden ignoriert.
    private static Set<String> loadExceptions() {
        Set<String> set = new HashSet<>();
        Path file = Paths.get("exceptions.txt");
        if (!Files.exists(file)) {
            logger.warn("exceptions.txt nicht gefunden - es werden keine Ausnahmen angewendet.");
            return set;
        }
        try {
            for (String line : Files.readAllLines(file)) {
                if (line == null) continue;
                String s = line.trim();
                if (s.isEmpty() || s.startsWith("#")) continue;
                set.add(s);
            }
            logger.info("Geladene Ausnahme-Kundennummern: " + set.size());
        } catch (IOException e) {
            logger.error("Fehler beim Lesen von exceptions.txt", e);
        }
        return set;
    }

    // Extrahiert die Kundennummer anhand der Regel:
    // Nach 'Fa_Rg_' oder 'Fa_Rg_NC_' ist die Kundennummer der 4. Block (durch '_' getrennt).
    private static Optional<String> extractCustomerFromFileName(String fileName) {
        if (fileName == null) return Optional.empty();
        String base = fileName;
        int dot = base.lastIndexOf('.');
        if (dot > 0) base = base.substring(0, dot);

        String[] parts = base.split("_");
        if (parts.length < 6) return Optional.empty(); // minimal erwartete Laenge

        int prefixLen;
        if (parts.length >= 3 && "Fa".equals(parts[0]) && "Rg".equals(parts[1]) && "NC".equals(parts[2])) {
            prefixLen = 3;
        } else if (parts.length >= 2 && "Fa".equals(parts[0]) && "Rg".equals(parts[1])) {
            prefixLen = 2;
        } else {
            return Optional.empty();
        }

        int idx = prefixLen + 3; // 4. Block nach dem Praefix
        if (idx < parts.length) {
            return Optional.of(parts[idx]);
        }
        return Optional.empty();
    }
}
