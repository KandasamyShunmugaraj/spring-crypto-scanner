package com.thesis.cryptoscanner;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.expr.IntegerLiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * SpringCryptoScanner — Spring Security-aware cryptographic asset discovery tool.
 *
 * Extends CBOMkit's Layer 4 (raw JCA) detection to cover:
 *   Layer 3 — Spring Security @Bean configurations
 *   Layer 2 — Spring Data @Convert field-level encryption
 *   Layer 1 — application.yml / pom.xml crypto configuration
 *
 * Produces CycloneDX 1.6-compliant CBOM JSON output.
 *
 * Thesis: Spring-Aware Cryptographic Asset Discovery
 * Author: Kandasamy S | IIT Jodhpur | M.Tech AI & Data Science
 */
public class SpringCryptoScanner {

    // ── Quantum Safety Classification ─────────────────────────────────────────
    private static final Map<String, String> QUANTUM_STATUS  = new HashMap<>();
    private static final Map<String, String> BREAK_REASON    = new HashMap<>();
    private static final Map<String, String> PQ_REPLACEMENT  = new HashMap<>();
    private static final Map<String, String> PRIMITIVE_TYPE  = new HashMap<>();

    static {
        // ── NOT QUANTUM SAFE (Shor's algorithm) ──────────────────────────────
        QUANTUM_STATUS.put("RSA",        "notQuantumSafe");
        QUANTUM_STATUS.put("EC",         "notQuantumSafe");
        QUANTUM_STATUS.put("ECDSA",      "notQuantumSafe");
        QUANTUM_STATUS.put("ECDH",       "notQuantumSafe");
        QUANTUM_STATUS.put("DSA",        "notQuantumSafe");
        QUANTUM_STATUS.put("DIFFIEHELLMAN", "notQuantumSafe");

        BREAK_REASON.put("RSA",   "Shor's algorithm solves integer factorisation in polynomial time O((log N)^3)");
        BREAK_REASON.put("EC",    "Shor's algorithm solves discrete logarithm on elliptic curves");
        BREAK_REASON.put("ECDSA", "Shor's algorithm solves discrete logarithm on elliptic curves");
        BREAK_REASON.put("ECDH",  "Shor's algorithm solves discrete logarithm on elliptic curves");
        BREAK_REASON.put("DSA",   "Shor's algorithm solves discrete logarithm problem");

        PQ_REPLACEMENT.put("RSA",   "ML-KEM (NIST FIPS 203) for key exchange; ML-DSA (NIST FIPS 204) for signatures");
        PQ_REPLACEMENT.put("EC",    "ML-KEM (NIST FIPS 203) for key exchange; ML-DSA (NIST FIPS 204) for signatures");
        PQ_REPLACEMENT.put("ECDSA", "ML-DSA (NIST FIPS 204) or SLH-DSA (NIST FIPS 205)");
        PQ_REPLACEMENT.put("ECDH",  "ML-KEM (NIST FIPS 203)");

        PRIMITIVE_TYPE.put("RSA",   "pke");
        PRIMITIVE_TYPE.put("EC",    "ecc");
        PRIMITIVE_TYPE.put("ECDSA", "signature");
        PRIMITIVE_TYPE.put("ECDH",  "keyAgreement");
        PRIMITIVE_TYPE.put("DSA",   "signature");

        // ── CLASSICALLY BROKEN (broken before quantum matters) ────────────────
        QUANTUM_STATUS.put("SHA-1",    "classicallyBroken");
        QUANTUM_STATUS.put("SHA1",     "classicallyBroken");
        QUANTUM_STATUS.put("MD5",      "classicallyBroken");
        QUANTUM_STATUS.put("DES",      "classicallyBroken");
        QUANTUM_STATUS.put("3DES",     "classicallyBroken");
        QUANTUM_STATUS.put("TRIPLEDES","classicallyBroken");
        QUANTUM_STATUS.put("RC4",      "classicallyBroken");
        QUANTUM_STATUS.put("BLOWFISH", "classicallyBroken");

        BREAK_REASON.put("SHA-1", "SHAttered attack (2017) produced SHA-1 collision on classical hardware");
        BREAK_REASON.put("MD5",   "Collision attacks demonstrated in 2004; preimage attacks feasible");
        BREAK_REASON.put("DES",   "56-bit key exhausted in 22 hours by EFF DES Cracker (1998)");
        BREAK_REASON.put("RC4",   "Multiple statistical biases; prohibited in TLS (RFC 7465)");
        BREAK_REASON.put("BLOWFISH", "64-bit block size — Birthday bound attacks at ~32GB data");

        PQ_REPLACEMENT.put("SHA-1", "SHA-256 or SHA-3 (NIST FIPS 180-4 / FIPS 202)");
        PQ_REPLACEMENT.put("MD5",   "SHA-256");
        PQ_REPLACEMENT.put("DES",   "AES-256-GCM");
        PQ_REPLACEMENT.put("3DES",  "AES-256-GCM");
        PQ_REPLACEMENT.put("RC4",   "ChaCha20-Poly1305 or AES-256-GCM");

        PRIMITIVE_TYPE.put("SHA-1", "hash");
        PRIMITIVE_TYPE.put("MD5",   "hash");
        PRIMITIVE_TYPE.put("DES",   "blockCipher");
        PRIMITIVE_TYPE.put("3DES",  "blockCipher");

        // ── QUANTUM SAFE (Grover's gives quadratic speedup only) ──────────────
        QUANTUM_STATUS.put("AES",        "quantumSafe");
        QUANTUM_STATUS.put("SHA-256",    "quantumSafe");
        QUANTUM_STATUS.put("SHA-384",    "quantumSafe");
        QUANTUM_STATUS.put("SHA-512",    "quantumSafe");
        QUANTUM_STATUS.put("SHA3-256",   "quantumSafe");
        QUANTUM_STATUS.put("SHA3-512",   "quantumSafe");
        QUANTUM_STATUS.put("HMACSHA256", "quantumSafe");
        QUANTUM_STATUS.put("HMACSHA512", "quantumSafe");
        QUANTUM_STATUS.put("ARGON2",     "quantumSafe");
        QUANTUM_STATUS.put("BCRYPT",     "quantumSafe");
        QUANTUM_STATUS.put("SCRYPT",     "quantumSafe");

        PRIMITIVE_TYPE.put("AES",        "blockCipher");
        PRIMITIVE_TYPE.put("SHA-256",    "hash");
        PRIMITIVE_TYPE.put("SHA-512",    "hash");
        PRIMITIVE_TYPE.put("HMACSHA256", "mac");
        PRIMITIVE_TYPE.put("HMACSHA512", "mac");
        PRIMITIVE_TYPE.put("BCRYPT",     "kdf");
        PRIMITIVE_TYPE.put("ARGON2",     "kdf");
    }

    // ── Finding model ──────────────────────────────────────────────────────────
    static class Finding {
        String rule;
        String file;
        int    line;
        String detail;
        String layer;
        String severity;
        String algorithm;       // extracted algorithm name
        String quantumStatus;   // quantumSafe / notQuantumSafe / classicallyBroken / unknown
        String primitive;       // hash / blockCipher / pke / mac / kdf / signature ...
        String replacement;     // recommended PQ replacement

        Finding(String rule, String file, int line, String detail,
                String layer, String severity, String algorithm) {
            this.rule          = rule;
            this.file          = file;
            this.line          = line;
            this.detail        = detail;
            this.layer         = layer;
            this.severity      = severity;
            this.algorithm     = algorithm;
            this.quantumStatus = resolveQuantumStatus(algorithm);
            this.primitive     = PRIMITIVE_TYPE.getOrDefault(
                    algorithm.toUpperCase(), "unknown");
            this.replacement   = PQ_REPLACEMENT.getOrDefault(
                    algorithm.toUpperCase(), "See NIST PQC standards");
        }

        static String resolveQuantumStatus(String algo) {
            if (algo == null || algo.isEmpty()) return "unknown";
            String up = algo.toUpperCase().trim();
            for (Map.Entry<String, String> e : QUANTUM_STATUS.entrySet()) {
                if (up.equals(e.getKey().toUpperCase()) ||
                        up.startsWith(e.getKey().toUpperCase() + "/") ||
                        up.startsWith(e.getKey().toUpperCase() + "-")) {
                    return e.getValue();
                }
            }
            return "unknown";
        }

        @Override
        public String toString() {
            return String.format("[%s] [%s] %s @ %s:%d — %s [quantum: %s]",
                    severity, layer, rule, file, line, detail, quantumStatus);
        }
    }

    // ── Scanner state ──────────────────────────────────────────────────────────
    private final String       projectPath;
    private final List<Finding> findings = new ArrayList<>();
    public  List<Finding> getFindings() { return findings; }
    private       String       projectName;

    public SpringCryptoScanner(String projectPath) {
        this.projectPath = projectPath;
        this.projectName = new File(projectPath).getName();
    }

    // ── Entry point ────────────────────────────────────────────────────────────
    public void scan() throws Exception {
        System.out.println("==============================================");
        System.out.println(" Spring Crypto Scanner — Thesis Tool v2.0");
        System.out.println(" CycloneDX 1.6 CBOM output enabled");
        System.out.println(" Scanning: " + projectPath);
        System.out.println("==============================================\n");

        // Walk all .java files
        try (Stream<Path> paths = Files.walk(Paths.get(projectPath))) {
            paths.filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> !p.getFileName().toString().equals("SpringCryptoScanner.java"))
                    .forEach(p -> {
                        try { scanJavaFile(p.toFile()); }
                        catch (Exception e) {
                            System.err.println("Could not parse: " + p);
                        }
                    });
        }

        // Scan YAML config
        scanYamlFile(projectPath + "/src/main/resources/application.yml");
        scanYamlFile(projectPath + "/src/main/resources/application.properties");

        // Scan pom.xml
        scanPomFile(projectPath + "/pom.xml");

        // Print human-readable report
        printReport();

        // Write CycloneDX CBOM JSON
        String cbomPath = projectPath + "/cbom-springscanner.json";
        writeCBOM(cbomPath);
        System.out.println("\n📄 CBOM JSON written to: " + cbomPath);
    }

    // ── Rule 1: BCrypt weak cost factor (Layer 3) ──────────────────────────────
    private void checkBCrypt(CompilationUnit cu, String fileName) {
        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {
            if (expr.getTypeAsString().equals("BCryptPasswordEncoder")) {
                if (!expr.getArguments().isEmpty()) {
                    expr.getArguments().get(0).ifIntegerLiteralExpr(lit -> {
                        int strength = Integer.parseInt(
                                lit.asIntegerLiteralExpr().getValue());
                        if (strength < 10) {
                            findings.add(new Finding(
                                    "WEAK_BCRYPT_COST_FACTOR",
                                    fileName,
                                    expr.getBegin().map(p -> p.line).orElse(0),
                                    "BCryptPasswordEncoder strength=" + strength +
                                            " (minimum safe value is 10). " +
                                            "At strength=" + strength + ", 2^" + strength +
                                            "=" + (int)Math.pow(2,strength) + " iterations — " +
                                            "brute-force feasible on modern hardware.",
                                    "L3-SpringSecurityBean",
                                    "HIGH",
                                    "BCrypt"
                            ));
                        }
                    });
                }
            }
        });
    }

    // ── Rule 2: NimbusJwtDecoder missing algorithm whitelist (Layer 3) ─────────
    private void checkJwtDecoder(CompilationUnit cu, String fileName) {
        cu.findAll(MethodCallExpr.class).forEach(expr -> {
            String name = expr.getNameAsString();
            if (name.equals("withSecretKey") || name.equals("withPublicKey")) {
                String fullExpr = expr.toString();
                if (!fullExpr.contains("setJwsAlgorithms") &&
                        !fullExpr.contains("jwsAlgorithm")) {
                    findings.add(new Finding(
                            "MISSING_JWT_ALGORITHM_WHITELIST",
                            fileName,
                            expr.getBegin().map(p -> p.line).orElse(0),
                            "NimbusJwtDecoder built without algorithm whitelist " +
                                    "(setJwsAlgorithms not called). " +
                                    "Vulnerable to JWT algorithm confusion attack: " +
                                    "attacker switches alg header from RS256 to HS256 " +
                                    "and signs with server public key as HMAC secret.",
                            "L3-SpringSecurityBean",
                            "CRITICAL",
                            "RSA"
                    ));
                }
            }
        });
    }

    // ── Rule 3: @Convert field encryption (Layer 2) ────────────────────────────
    private void checkConvertAnnotation(CompilationUnit cu, String fileName) {
        cu.findAll(FieldDeclaration.class).forEach(field -> {
            field.getAnnotations().forEach(ann -> {
                if (ann.getNameAsString().equals("Convert")) {
                    String fieldName = field.getVariables().isNonEmpty()
                            ? field.getVariable(0).getNameAsString()
                            : "unknown";
                    findings.add(new Finding(
                            "FIELD_LEVEL_ENCRYPTION_DETECTED",
                            fileName,
                            field.getBegin().map(p -> p.line).orElse(0),
                            "@Convert annotation on field '" + fieldName +
                                    "' — field-level encryption via AttributeConverter. " +
                                    "Audit converter class: verify algorithm is not AES/ECB, " +
                                    "key is not hardcoded, key size is AES-256 minimum. " +
                                    "CBOMkit cannot trace this annotation to its implementation.",
                            "L2-JPAConverter",
                            "MEDIUM",
                            "unknown"
                    ));
                }
            });
        });
    }

    // ── Rule 4: Weak/deprecated algorithm strings (Layer 4) ───────────────────
    private void checkWeakAlgorithms(CompilationUnit cu, String fileName) {
        cu.findAll(StringLiteralExpr.class).forEach(str -> {
            String val  = str.asString().trim();
            String valU = val.toUpperCase();
            int    line = str.getBegin().map(p -> p.line).orElse(0);

            // ECB mode — classically insecure
            if (valU.contains("/ECB/") || valU.equals("ECB")) {
                findings.add(new Finding(
                        "INSECURE_CIPHER_MODE_ECB",
                        fileName, line,
                        "ECB mode in cipher specification '" + val + "'. " +
                                "ECB is deterministic: identical plaintext blocks → " +
                                "identical ciphertext. Pattern analysis attacks are trivial. " +
                                "Replace with AES/GCM/NoPadding.",
                        "L4-RawJCA",
                        "CRITICAL",
                        "AES-ECB"
                ));
                return;
            }

            // Check against known algorithm classification table
            for (Map.Entry<String, String> e : QUANTUM_STATUS.entrySet()) {
                String algo   = e.getKey();
                String status = e.getValue();
                String algoU  = algo.toUpperCase();

                boolean matches = valU.equals(algoU)
                        || valU.startsWith(algoU + "/")
                        || valU.startsWith(algoU + "-")
                        || valU.startsWith("HMACWITH" + algoU)
                        || (valU.contains("WITH" + algoU));

                if (matches) {
                    if (status.equals("notQuantumSafe")) {
                        String reason  = BREAK_REASON.getOrDefault(algo,
                                "Vulnerable to Shor's algorithm");
                        String replace = PQ_REPLACEMENT.getOrDefault(algo,
                                "See NIST FIPS 203/204/205");
                        findings.add(new Finding(
                                "QUANTUM_VULNERABLE_ALGORITHM",
                                fileName, line,
                                "Quantum-vulnerable algorithm '" + val + "'. " +
                                        reason + ". Replace with: " + replace,
                                "L4-RawJCA",
                                "CRITICAL",
                                algo
                        ));
                    } else if (status.equals("classicallyBroken")) {
                        String reason  = BREAK_REASON.getOrDefault(algo,
                                "Classically broken algorithm");
                        String replace = PQ_REPLACEMENT.getOrDefault(algo,
                                "SHA-256 or AES-256-GCM");
                        findings.add(new Finding(
                                "CLASSICALLY_BROKEN_ALGORITHM",
                                fileName, line,
                                "Classically broken algorithm '" + val + "'. " +
                                        reason + ". Replace with: " + replace,
                                "L4-RawJCA",
                                "HIGH",
                                algo
                        ));
                    } else if (status.equals("quantumSafe")) {
                        // Only flag AES-128 specifically
                        if (algoU.equals("AES") && valU.contains("128")) {
                            findings.add(new Finding(
                                    "WEAK_KEY_SIZE",
                                    fileName, line,
                                    "AES-128 detected. Grover's algorithm reduces " +
                                            "effective security to 64 bits post-quantum. " +
                                            "Upgrade to AES-256.",
                                    "L4-RawJCA",
                                    "MEDIUM",
                                    "AES-128"
                            ));
                        }
                    }
                    return; // matched — stop checking
                }
            }
        });
    }

    // ── Rule 5: YAML config scanning (Layer 1) ─────────────────────────────────
    private void scanYamlFile(String yamlPath) {
        File f = new File(yamlPath);
        if (!f.exists()) return;
        try {
            List<String> lines = Files.readAllLines(f.toPath());
            for (int i = 0; i < lines.size(); i++) {
                String line  = lines.get(i).trim().toLowerCase();
                int    lineN = i + 1;

                if (line.contains("key-store-type") && line.contains("jks")) {
                    findings.add(new Finding(
                            "DEPRECATED_KEYSTORE_TYPE",
                            f.getName(), lineN,
                            "JKS keystore type is deprecated since Java 9. " +
                                    "JKS uses proprietary format with weaker protections. " +
                                    "Migrate to PKCS12 (key-store-type: PKCS12).",
                            "L1-ConfigFile",
                            "MEDIUM",
                            "JKS"
                    ));
                }

                if (line.contains("secret") && line.contains(":") &&
                        !line.trim().startsWith("#")) {
                    String[] parts = line.split(":", 2);
                    if (parts.length > 1) {
                        String val = parts[1].trim().replaceAll("[\"']","");
                        if (!val.isEmpty() && val.length() < 32) {
                            findings.add(new Finding(
                                    "WEAK_SECRET_IN_CONFIG",
                                    f.getName(), lineN,
                                    "Short secret value detected (< 32 chars). " +
                                            "Cryptographic secrets should be minimum 256 bits " +
                                            "(32 bytes) and stored in a secrets manager, " +
                                            "not in configuration files.",
                                    "L1-ConfigFile",
                                    "CRITICAL",
                                    "HMAC-secret"
                            ));
                        }
                    }
                }

                if (line.contains("protocol") &&
                        (line.contains(": tls") || line.contains("=tls")) &&
                        !line.contains("tlsv1.3") && !line.contains("tls1.3")) {
                    findings.add(new Finding(
                            "TLS_VERSION_NOT_PINNED",
                            f.getName(), lineN,
                            "TLS protocol not pinned to TLSv1.3. " +
                                    "Unspecified TLS version may allow TLS 1.2 with weak " +
                                    "cipher suites. Set: server.ssl.protocol=TLSv1.3",
                            "L1-ConfigFile",
                            "MEDIUM",
                            "TLS"
                    ));
                }
            }
        } catch (Exception e) {
            System.err.println("Could not read YAML: " + e.getMessage());
        }
    }

    // ── Rule 6: Maven dependency version check (Layer 1) ──────────────────────
    private void scanPomFile(String pomPath) {
        File f = new File(pomPath);
        if (!f.exists()) return;
        try {
            String content = new String(Files.readAllBytes(f.toPath()));
            if (content.contains("bcprov-jdk15on")) {
                findings.add(new Finding(
                        "LEGACY_BOUNCY_CASTLE",
                        "pom.xml", 0,
                        "Legacy BouncyCastle artifact 'bcprov-jdk15on' detected. " +
                                "This artifact targets Java 1.5 and is no longer maintained. " +
                                "Migrate to 'bcprov-jdk18on'.",
                        "L1-MavenDependency",
                        "MEDIUM",
                        "BouncyCastle"
                ));
            }
            if (content.contains("nimbus-jose-jwt")) {
                findings.add(new Finding(
                        "NIMBUS_JOSE_JWT_PRESENT",
                        "pom.xml", 0,
                        "nimbus-jose-jwt detected. Verify version is >= 10.0.1 " +
                                "to avoid CVE-2025-53864 (uncontrolled recursion, DoS). " +
                                "This library underpins Spring Security's JWT handling.",
                        "L1-MavenDependency",
                        "INFO",
                        "HMAC"
                ));
            }
        } catch (Exception e) {
            System.err.println("Could not read pom.xml: " + e.getMessage());
        }
    }

    // ── Scan a single Java file ────────────────────────────────────────────────
    private void scanJavaFile(File file) throws Exception {
        CompilationUnit cu   = StaticJavaParser.parse(new FileInputStream(file));
        String          name = file.getName();
        checkBCrypt(cu, name);
        checkJwtDecoder(cu, name);
        checkConvertAnnotation(cu, name);
        checkWeakAlgorithms(cu, name);
    }

    // ── Print human-readable report ────────────────────────────────────────────
    private void printReport() {
        System.out.println("\n══════════════════════════════════════════════");
        System.out.println(" SCAN RESULTS — " + findings.size() + " findings");
        System.out.println("══════════════════════════════════════════════\n");

        String[] layers = {
                "L1-ConfigFile","L1-MavenDependency",
                "L2-JPAConverter","L3-SpringSecurityBean","L4-RawJCA"
        };

        for (String layer : layers) {
            List<Finding> lf = findings.stream()
                    .filter(f -> f.layer.equals(layer)).toList();
            if (!lf.isEmpty()) {
                System.out.println("── " + layer + " ──────────────────────");
                lf.forEach(f -> System.out.println("  " + f));
                System.out.println();
            }
        }

        // Quantum safety summary
        long qVuln = findings.stream()
                .filter(f -> "notQuantumSafe".equals(f.quantumStatus)).count();
        long cBroken = findings.stream()
                .filter(f -> "classicallyBroken".equals(f.quantumStatus)).count();
        long qSafe = findings.stream()
                .filter(f -> "quantumSafe".equals(f.quantumStatus)).count();
        long critical = findings.stream()
                .filter(f -> "CRITICAL".equals(f.severity)).count();
        long high = findings.stream()
                .filter(f -> "HIGH".equals(f.severity)).count();
        long medium = findings.stream()
                .filter(f -> "MEDIUM".equals(f.severity)).count();

        System.out.println("══════════════════════════════════════════════");
        System.out.println(" SEVERITY SUMMARY");
        System.out.println(" CRITICAL : " + critical);
        System.out.println(" HIGH     : " + high);
        System.out.println(" MEDIUM   : " + medium);
        System.out.println("──────────────────────────────────────────────");
        System.out.println(" QUANTUM SAFETY SUMMARY");
        System.out.printf(" Quantum-vulnerable (Shor's)  : %d — replace with ML-KEM/ML-DSA%n", qVuln);
        System.out.printf(" Classically broken           : %d — replace immediately%n", cBroken);
        System.out.printf(" Quantum-safe                 : %d — no algorithm change needed%n", qSafe);
        System.out.println("══════════════════════════════════════════════");
    }

    // ── Write CycloneDX 1.6-compliant CBOM JSON ───────────────────────────────
    private void writeCBOM(String outputPath) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"bomFormat\": \"CycloneDX\",\n");
        sb.append("  \"specVersion\": \"1.6\",\n");
        sb.append("  \"serialNumber\": \"urn:uuid:").append(UUID.randomUUID()).append("\",\n");
        sb.append("  \"version\": 1,\n");

        // Metadata
        sb.append("  \"metadata\": {\n");
        sb.append("    \"timestamp\": \"").append(Instant.now()).append("\",\n");
        sb.append("    \"tools\": [\n");
        sb.append("      {\n");
        sb.append("        \"vendor\": \"IIT Jodhpur\",\n");
        sb.append("        \"name\": \"SpringCryptoScanner\",\n");
        sb.append("        \"version\": \"2.0\",\n");
        sb.append("        \"description\": \"Spring Security-aware cryptographic asset discovery tool. ");
        sb.append("Extends CBOMkit to cover Spring Security beans (Layer 3), ");
        sb.append("JPA @Convert annotations (Layer 2), and YAML/pom.xml config (Layer 1).\"\n");
        sb.append("      }\n");
        sb.append("    ],\n");
        sb.append("    \"component\": {\n");
        sb.append("      \"type\": \"application\",\n");
        sb.append("      \"name\": \"").append(escapeJson(projectName)).append("\",\n");
        sb.append("      \"version\": \"1.0\"\n");
        sb.append("    }\n");
        sb.append("  },\n");

        // Components — one per finding
        sb.append("  \"components\": [\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            sb.append("    {\n");
            sb.append("      \"type\": \"cryptographic-asset\",\n");
            sb.append("      \"bom-ref\": \"crypto/").append(f.layer).append("/")
                    .append(f.algorithm.replaceAll("[^a-zA-Z0-9]","_")).append("-")
                    .append(i).append("\",\n");
            sb.append("      \"name\": \"").append(escapeJson(f.algorithm)).append("\",\n");
            sb.append("      \"description\": \"").append(escapeJson(f.detail)).append("\",\n");

            // cryptoProperties — CycloneDX 1.6 schema
            sb.append("      \"cryptoProperties\": {\n");
            sb.append("        \"assetType\": \"algorithm\",\n");
            sb.append("        \"algorithmProperties\": {\n");
            sb.append("          \"primitive\": \"").append(escapeJson(f.primitive)).append("\",\n");
            sb.append("          \"executionEnvironment\": \"software-plain-ram\",\n");

            // Map quantum status to CycloneDX nistQuantumSecurityLevel
            String nistLevel = mapToNistLevel(f.quantumStatus);
            sb.append("          \"nistQuantumSecurityLevel\": ").append(nistLevel).append("\n");
            sb.append("        },\n");

            sb.append("        \"oid\": \"\"\n");
            sb.append("      },\n");

            // Properties — extended metadata
            sb.append("      \"properties\": [\n");
            sb.append("        {\"name\": \"spring-layer\",       \"value\": \"")
                    .append(escapeJson(f.layer)).append("\"},\n");
            sb.append("        {\"name\": \"detection-rule\",     \"value\": \"")
                    .append(escapeJson(f.rule)).append("\"},\n");
            sb.append("        {\"name\": \"severity\",           \"value\": \"")
                    .append(escapeJson(f.severity)).append("\"},\n");
            sb.append("        {\"name\": \"quantum-status\",     \"value\": \"")
                    .append(escapeJson(f.quantumStatus)).append("\"},\n");
            sb.append("        {\"name\": \"source-file\",        \"value\": \"")
                    .append(escapeJson(f.file)).append("\"},\n");
            sb.append("        {\"name\": \"source-line\",        \"value\": \"")
                    .append(f.line).append("\"},\n");
            sb.append("        {\"name\": \"pq-replacement\",     \"value\": \"")
                    .append(escapeJson(f.replacement)).append("\"},\n");
            sb.append("        {\"name\": \"cbomkit-detects\",    \"value\": \"")
                    .append(f.layer.equals("L4-RawJCA") ? "true" : "false").append("\"}\n");
            sb.append("      ]\n");

            sb.append("    }");
            if (i < findings.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        // Summary vulnerabilities section
        sb.append("  \"vulnerabilities\": [],\n");

        // Extension — SpringCryptoScanner summary
        sb.append("  \"extensions\": [\n");
        sb.append("    {\n");
        sb.append("      \"namespace\": \"https://github.com/KandasamyShunmugaraj/crypto-gap-test\",\n");
        sb.append("      \"springCryptoScannerSummary\": {\n");
        sb.append("        \"totalFindings\": ").append(findings.size()).append(",\n");
        sb.append("        \"layer1Findings\": ").append(
                findings.stream().filter(f -> f.layer.startsWith("L1")).count()).append(",\n");
        sb.append("        \"layer2Findings\": ").append(
                findings.stream().filter(f -> f.layer.startsWith("L2")).count()).append(",\n");
        sb.append("        \"layer3Findings\": ").append(
                findings.stream().filter(f -> f.layer.startsWith("L3")).count()).append(",\n");
        sb.append("        \"layer4Findings\": ").append(
                findings.stream().filter(f -> f.layer.startsWith("L4")).count()).append(",\n");
        sb.append("        \"quantumVulnerable\": ").append(
                findings.stream().filter(f -> "notQuantumSafe".equals(f.quantumStatus)).count()).append(",\n");
        sb.append("        \"classicallyBroken\": ").append(
                findings.stream().filter(f -> "classicallyBroken".equals(f.quantumStatus)).count()).append(",\n");
        sb.append("        \"cbomkitWouldMiss\": ").append(
                findings.stream().filter(f -> !f.layer.equals("L4-RawJCA")).count()).append(",\n");
        sb.append("        \"note\": \"Layers 1-3 findings are invisible to CBOMkit 2.2.0. ");
        sb.append("This CBOM extends CBOMkit coverage to Spring Security framework layer.\"\n");
        sb.append("      }\n");
        sb.append("    }\n");
        sb.append("  ]\n");
        sb.append("}\n");

        try (FileWriter fw = new FileWriter(outputPath)) {
            fw.write(sb.toString());
        }
    }

    // Map quantum status to NIST quantum security level (0-6)
    private String mapToNistLevel(String status) {
        switch (status) {
            case "notQuantumSafe":    return "0";  // broken by quantum
            case "classicallyBroken": return "0";  // already broken
            case "quantumSafe":       return "5";  // NIST level 5 = AES-256 equivalent
            default:                  return "0";
        }
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\","\\\\")
                .replace("\"","\\\"")
                .replace("\n","\\n")
                .replace("\r","\\r")
                .replace("\t","\\t");
    }

    // ── Main ───────────────────────────────────────────────────────────────────
    public static void main(String[] args) throws Exception {
        String projectPath = args.length > 0
                ? args[0]
                : System.getProperty("user.home") + "/thesis/crypto-gap-test";
        new SpringCryptoScanner(projectPath).scan();
    }
}
