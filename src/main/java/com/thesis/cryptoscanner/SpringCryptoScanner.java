package com.thesis.cryptoscanner;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.IntegerLiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * SpringCryptoScanner v2.0
 *
 * Design goal: find everything CBOMkit finds (Layer 4 raw JCA)
 * PLUS everything CBOMkit misses (Layers 1-3 Spring abstractions).
 *
 * Layer 4 - Raw JCA (matches CBOMkit):
 *   MessageDigest.getInstance(), Cipher.getInstance(), KeyPairGenerator.getInstance(),
 *   KeyGenerator.getInstance(), SecretKeyFactory.getInstance(), Mac.getInstance(),
 *   Signature.getInstance(), JJWT SignatureAlgorithm enums
 *
 * Layer 3 - Spring Security @Bean (CBOMkit misses):
 *   BCryptPasswordEncoder(k < 10), NimbusJwtDecoder without setJwsAlgorithms()
 *
 * Layer 2 - Spring Data @Convert (CBOMkit misses):
 *   @Convert on JPA entity fields
 *
 * Layer 1 - Configuration (CBOMkit misses):
 *   application.yml (JKS keystore, weak secrets, TLS), pom.xml (legacy crypto deps)
 *
 * Output: CycloneDX 1.6 CBOM JSON with cbomkit-detects field per finding.
 *
 * Thesis: Spring-Aware Cryptographic Asset Discovery
 * Author: Kandasamy | IIT Jodhpur | M25AID042
 */
public class SpringCryptoScanner {

    // ── Classification Maps ────────────────────────────────────────────────────
    private static final Map<String, String> QUANTUM_STATUS = new HashMap<>();
    private static final Map<String, String> BREAK_REASON   = new HashMap<>();
    private static final Map<String, String> PQ_REPLACEMENT = new HashMap<>();
    private static final Map<String, String> PRIMITIVE_TYPE = new HashMap<>();

    // JCA service class names — same set CBOMkit scans
    private static final Set<String> JCA_SERVICES = new HashSet<>(Arrays.asList(
        "MessageDigest", "Cipher", "KeyPairGenerator", "KeyGenerator",
        "SecretKeyFactory", "Mac", "Signature", "KeyAgreement",
        "AlgorithmParameters", "AlgorithmParameterGenerator",
        "SecureRandom", "CertificateFactory",
        // Additional JCA classes CBOMkit also scans
        "KeyFactory", "KeyStore", "TrustManagerFactory",
        "KeyManagerFactory", "SSLContext", "CertPathBuilder",
        "CertPathValidator", "CertStore"
    ));

    static {
        // NOT QUANTUM SAFE — Shor's algorithm breaks these
        QUANTUM_STATUS.put("RSA",          "notQuantumSafe");
        QUANTUM_STATUS.put("EC",           "notQuantumSafe");
        QUANTUM_STATUS.put("ECDSA",        "notQuantumSafe");
        QUANTUM_STATUS.put("ECDH",         "notQuantumSafe");
        QUANTUM_STATUS.put("DSA",          "notQuantumSafe");
        QUANTUM_STATUS.put("DIFFIEHELLMAN","notQuantumSafe");
        QUANTUM_STATUS.put("DH",           "notQuantumSafe");

        BREAK_REASON.put("RSA",   "Shor's algorithm solves integer factorisation in polynomial time O((log N)^3)");
        BREAK_REASON.put("EC",    "Shor's algorithm solves discrete logarithm on elliptic curves");
        BREAK_REASON.put("ECDSA", "Shor's algorithm solves discrete logarithm on elliptic curves");
        BREAK_REASON.put("ECDH",  "Shor's algorithm solves discrete logarithm on elliptic curves");
        BREAK_REASON.put("DSA",   "Shor's algorithm solves discrete logarithm problem");
        BREAK_REASON.put("DH",    "Shor's algorithm solves discrete logarithm problem");

        PQ_REPLACEMENT.put("RSA",   "ML-KEM (NIST FIPS 203) for key exchange; ML-DSA (NIST FIPS 204) for signatures");
        PQ_REPLACEMENT.put("EC",    "ML-KEM (NIST FIPS 203) for key exchange; ML-DSA (NIST FIPS 204) for signatures");
        PQ_REPLACEMENT.put("ECDSA", "ML-DSA (NIST FIPS 204) or SLH-DSA (NIST FIPS 205)");
        PQ_REPLACEMENT.put("ECDH",  "ML-KEM (NIST FIPS 203)");
        PQ_REPLACEMENT.put("DSA",   "ML-DSA (NIST FIPS 204)");
        PQ_REPLACEMENT.put("DH",    "ML-KEM (NIST FIPS 203)");

        PRIMITIVE_TYPE.put("RSA",   "pke");
        PRIMITIVE_TYPE.put("EC",    "ecc");
        PRIMITIVE_TYPE.put("ECDSA", "signature");
        PRIMITIVE_TYPE.put("ECDH",  "keyAgreement");
        PRIMITIVE_TYPE.put("DSA",   "signature");
        PRIMITIVE_TYPE.put("DH",    "keyAgreement");

        // CLASSICALLY BROKEN — broken today on classical computers
        QUANTUM_STATUS.put("SHA-1",     "classicallyBroken");
        QUANTUM_STATUS.put("SHA1",      "classicallyBroken");
        QUANTUM_STATUS.put("MD5",       "classicallyBroken");
        QUANTUM_STATUS.put("MD2",       "classicallyBroken");
        QUANTUM_STATUS.put("DES",       "classicallyBroken");
        QUANTUM_STATUS.put("3DES",      "classicallyBroken");
        QUANTUM_STATUS.put("TRIPLEDES", "classicallyBroken");
        QUANTUM_STATUS.put("DESEDE",    "classicallyBroken");
        QUANTUM_STATUS.put("RC4",       "classicallyBroken");
        QUANTUM_STATUS.put("RC2",       "classicallyBroken");
        QUANTUM_STATUS.put("BLOWFISH",  "classicallyBroken");

        BREAK_REASON.put("SHA-1",    "SHAttered attack (2017) produced SHA-1 collision on classical hardware");
        BREAK_REASON.put("MD5",      "Collision attacks demonstrated in 2004 (Wang & Yu, EUROCRYPT 2004)");
        BREAK_REASON.put("DES",      "56-bit key exhausted in 22 hours by EFF DES Cracker (1998)");
        BREAK_REASON.put("3DES",     "Sweet32 Birthday attack; deprecated by NIST SP 800-131A Rev 2");
        BREAK_REASON.put("DESEDE",   "Sweet32 Birthday attack; deprecated by NIST SP 800-131A Rev 2");
        BREAK_REASON.put("RC4",      "Multiple statistical biases; prohibited in TLS by RFC 7465");
        BREAK_REASON.put("BLOWFISH", "64-bit block size — Birthday bound attacks at ~32GB data");

        PQ_REPLACEMENT.put("SHA-1",    "SHA-256 or SHA-3 (NIST FIPS 180-4 / FIPS 202)");
        PQ_REPLACEMENT.put("MD5",      "SHA-256 (NIST FIPS 180-4)");
        PQ_REPLACEMENT.put("DES",      "AES-256-GCM");
        PQ_REPLACEMENT.put("3DES",     "AES-256-GCM");
        PQ_REPLACEMENT.put("DESEDE",   "AES-256-GCM");
        PQ_REPLACEMENT.put("RC4",      "ChaCha20-Poly1305 or AES-256-GCM");
        PQ_REPLACEMENT.put("BLOWFISH", "AES-256-GCM");

        PRIMITIVE_TYPE.put("SHA-1",    "hash");
        PRIMITIVE_TYPE.put("MD5",      "hash");
        PRIMITIVE_TYPE.put("DES",      "blockCipher");
        PRIMITIVE_TYPE.put("3DES",     "blockCipher");
        PRIMITIVE_TYPE.put("DESEDE",   "blockCipher");

        // QUANTUM SAFE — Grover's only quadratic speedup
        QUANTUM_STATUS.put("AES",        "quantumSafe");
        QUANTUM_STATUS.put("SHA-256",    "quantumSafe");
        QUANTUM_STATUS.put("SHA-384",    "quantumSafe");
        QUANTUM_STATUS.put("SHA-512",    "quantumSafe");
        QUANTUM_STATUS.put("SHA3-256",   "quantumSafe");
        QUANTUM_STATUS.put("SHA3-384",   "quantumSafe");
        QUANTUM_STATUS.put("SHA3-512",   "quantumSafe");
        QUANTUM_STATUS.put("HMACSHA256", "quantumSafe");
        QUANTUM_STATUS.put("HMACSHA384", "quantumSafe");
        QUANTUM_STATUS.put("HMACSHA512", "quantumSafe");
        QUANTUM_STATUS.put("HMAC-SHA256","quantumSafe");
        QUANTUM_STATUS.put("HMAC-SHA512","quantumSafe");
        QUANTUM_STATUS.put("ARGON2",     "quantumSafe");
        QUANTUM_STATUS.put("BCRYPT",     "quantumSafe");
        QUANTUM_STATUS.put("SCRYPT",     "quantumSafe");
        QUANTUM_STATUS.put("PBKDF2",     "quantumSafe");
        QUANTUM_STATUS.put("CHACHA20",   "quantumSafe");

        PRIMITIVE_TYPE.put("AES",        "blockCipher");
        PRIMITIVE_TYPE.put("SHA-256",    "hash");
        PRIMITIVE_TYPE.put("SHA-384",    "hash");
        PRIMITIVE_TYPE.put("SHA-512",    "hash");
        PRIMITIVE_TYPE.put("SHA3-256",   "hash");
        PRIMITIVE_TYPE.put("SHA3-512",   "hash");
        PRIMITIVE_TYPE.put("HMACSHA256", "mac");
        PRIMITIVE_TYPE.put("HMACSHA512", "mac");
        PRIMITIVE_TYPE.put("HMAC-SHA256","mac");
        PRIMITIVE_TYPE.put("HMAC-SHA512","mac");
        PRIMITIVE_TYPE.put("BCRYPT",     "kdf");
        PRIMITIVE_TYPE.put("ARGON2",     "kdf");
        PRIMITIVE_TYPE.put("SCRYPT",     "kdf");
        PRIMITIVE_TYPE.put("PBKDF2",     "kdf");
    }

    // ── Finding model ──────────────────────────────────────────────────────────
    public static class Finding {
        public String rule;
        public String file;
        public int    line;
        public String detail;
        public String layer;
        public String severity;
        public String algorithm;
        public String quantumStatus;
        public String primitive;
        public String replacement;

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
            this.primitive     = PRIMITIVE_TYPE.getOrDefault(algorithm.toUpperCase(), "unknown");
            this.replacement   = PQ_REPLACEMENT.getOrDefault(algorithm.toUpperCase(), "See NIST PQC standards");
        }

        static String resolveQuantumStatus(String algo) {
            if (algo == null || algo.isEmpty()) return "unknown";
            String up = algo.toUpperCase().trim();

            // Direct match or prefix match
            for (Map.Entry<String, String> e : QUANTUM_STATUS.entrySet()) {
                String key = e.getKey().toUpperCase();
                if (up.equals(key) || up.startsWith(key + "/") || up.startsWith(key + "-")
                    || up.contains("WITH" + key)) {
                    return e.getValue();
                }
            }

            // Common algorithm families not in exact table
            if (up.startsWith("HMAC")) return "quantumSafe";
            if (up.startsWith("AES"))  return "quantumSafe";
            if (up.startsWith("SHA-2") || up.startsWith("SHA-3") || up.startsWith("SHA2") || up.startsWith("SHA3")) return "quantumSafe";
            if (up.startsWith("SHA-1") || up.equals("SHA1")) return "classicallyBroken";
            if (up.startsWith("RSA"))  return "notQuantumSafe";
            if (up.startsWith("EC") || up.startsWith("ECDSA") || up.startsWith("ECDH")) return "notQuantumSafe";
            if (up.contains("JKS"))    return "quantumSafe"; // keystore format — not an algorithm
            if (up.contains("TLS"))    return "quantumSafe"; // protocol
            if (up.contains("OAUTH")) return "quantumSafe";  // framework concept

            return "unknown";
        }

        @Override
        public String toString() {
            return String.format("[%s] [%s] %s @ %s:%d — %s [quantum: %s]",
                severity, layer, rule, file, line, detail, quantumStatus);
        }
    }

    // ── Scanner state ──────────────────────────────────────────────────────────
    private final String        projectPath;
    private final List<Finding> findings = new ArrayList<>();
    public  List<Finding> getFindings() { return findings; }
    private       String        projectName;
    private       String        sourceUrl    = "";
    private       String        sourceCommit = "";
    private       String        sourceBranch = "";

    public void setSourceInfo(String url, String commit, String branch) {
        this.sourceUrl    = url    != null ? url    : "";
        this.sourceCommit = commit != null ? commit : "";
        this.sourceBranch = branch != null ? branch : "";
    }

    public SpringCryptoScanner(String projectPath) {
        this.projectPath = projectPath;
        this.projectName = new File(projectPath).getName();
    }

    // ── Entry point ────────────────────────────────────────────────────────────
    public void scan() throws Exception {
        System.out.println("==============================================");
        System.out.println(" Spring Crypto Scanner v2.0");
        System.out.println(" Goal: CBOMkit L4 coverage + Spring L1/L2/L3");
        System.out.println(" Scanning: " + projectPath);
        System.out.println("==============================================\n");

        try (Stream<Path> paths = Files.walk(Paths.get(projectPath))) {
            paths.filter(p -> p.toString().endsWith(".java"))
                 .filter(p -> !p.getFileName().toString().equals("SpringCryptoScanner.java"))
                 // Exclude test directories — CBOMkit scans production code only
                 // Ensures scan scope matches CBOMkit for fair comparison
                 .filter(p -> {
                     String ps = p.toString().replace("\\", "/");
                     return !ps.contains("/src/test/")
                         && !ps.contains("/test/java/")
                         && !ps.contains("/tests/");
                 })
                 .forEach(p -> {
                     try { scanJavaFile(p.toFile()); }
                     catch (Exception e) { System.err.println("Could not parse: " + p); }
                 });
        }

        scanYamlFile(projectPath + "/src/main/resources/application.yml");
        scanYamlFile(projectPath + "/src/main/resources/application.properties");
        scanPomFile(projectPath + "/pom.xml");
        printReport();

        String cbomPath = projectPath + "/cbom-springscanner.json";
        writeCBOM(cbomPath);
        System.out.println("\n CBOM JSON written to: " + cbomPath);
    }

    private void scanJavaFile(File file) throws Exception {
        CompilationUnit cu   = StaticJavaParser.parse(new FileInputStream(file));
        // Use relative path from project root so full package path is visible
        // e.g. "src/main/java/com/example/security/SecurityConfiguration.java"
        // instead of just "SecurityConfiguration.java"
        String name;
        try {
            name = Paths.get(projectPath).relativize(file.toPath()).toString();
        } catch (Exception e) {
            name = file.getName();
        }
        // Layer 3
        checkBCrypt(cu, name);
        checkJwtDecoder(cu, name);
        // Layer 2
        checkConvertAnnotation(cu, name);
        // Layer 4 — three sub-rules together matching CBOMkit + extending it
        checkJcaGetInstance(cu, name);
        checkSecretKeySpec(cu, name);    // NEW: new SecretKeySpec(bytes, "AES")
        checkWeakAlgorithmStrings(cu, name);
        checkJwtLibraryEnums(cu, name);
    }

    // ═══════════════════════════════════════════════════════════
    // LAYER 3 — Spring Security @Bean (CBOMkit misses these)
    // ═══════════════════════════════════════════════════════════

    private void checkBCrypt(CompilationUnit cu, String fileName) {
        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {
            if (!expr.getTypeAsString().equals("BCryptPasswordEncoder")) return;
            if (expr.getArguments().isEmpty()) return;
            expr.getArguments().get(0).ifIntegerLiteralExpr(lit -> {
                int strength = Integer.parseInt(lit.getValue());
                if (strength < 10) {
                    findings.add(new Finding(
                        "WEAK_BCRYPT_COST_FACTOR", fileName,
                        expr.getBegin().map(p -> p.line).orElse(0),
                        "BCryptPasswordEncoder(strength=" + strength + "). OWASP minimum is 10. " +
                        "2^" + strength + "=" + (int)Math.pow(2,strength) + " iterations — brute-force feasible. " +
                        "CBOMkit misses this (Spring bean, not JCA getInstance).",
                        "L3-SpringSecurityBean", "HIGH", "BCrypt"
                    ));
                }
            });
        });
    }

    private void checkJwtDecoder(CompilationUnit cu, String fileName) {
        cu.findAll(MethodCallExpr.class).forEach(expr -> {
            String name = expr.getNameAsString();
            if (!name.equals("withSecretKey") && !name.equals("withPublicKey")) return;
            String full = expr.toString();
            if (!full.contains("setJwsAlgorithms") && !full.contains("jwsAlgorithm")) {
                findings.add(new Finding(
                    "MISSING_JWT_ALGORITHM_WHITELIST", fileName,
                    expr.getBegin().map(p -> p.line).orElse(0),
                    "NimbusJwtDecoder." + name + "() without setJwsAlgorithms(). " +
                    "Vulnerable to JWT algorithm confusion attack (attacker switches RS256 to HS256). " +
                    "CBOMkit misses this (Spring Security builder, not JCA getInstance).",
                    "L3-SpringSecurityBean", "CRITICAL", "RSA"
                ));
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // LAYER 2 — Spring Data @Convert (CBOMkit misses these)
    // ═══════════════════════════════════════════════════════════

    private void checkConvertAnnotation(CompilationUnit cu, String fileName) {
        cu.findAll(FieldDeclaration.class).forEach(field -> {
            field.getAnnotations().forEach(ann -> {
                if (!ann.getNameAsString().equals("Convert")) return;
                String fieldName = field.getVariables().isNonEmpty()
                    ? field.getVariables().get(0).getNameAsString() : "unknown";
                findings.add(new Finding(
                    "FIELD_LEVEL_ENCRYPTION_DETECTED", fileName,
                    field.getBegin().map(p -> p.line).orElse(0),
                    "@Convert on field '" + fieldName + "' — JPA field-level encryption. " +
                    "Audit converter: verify AES-256-GCM (not ECB), no hardcoded key. " +
                    "CBOMkit misses this (annotation, not JCA instanceof call).",
                    "L2-JPAConverter", "MEDIUM", "unknown"
                ));
            });
        });
    }

    // ═══════════════════════════════════════════════════════════
    // LAYER 4 — Raw JCA (CBOMkit finds THESE — we match + extend)
    // ═══════════════════════════════════════════════════════════

    /**
     * Rule 4a — JCA getInstance() detection.
     * PRIMARY rule that matches CBOMkit's core detection logic exactly.
     * Detects: MessageDigest.getInstance("SHA-1"), Cipher.getInstance("AES/ECB"),
     *          KeyPairGenerator.getInstance("RSA"), Mac.getInstance("HmacSHA256"), etc.
     */
    private void checkJcaGetInstance(CompilationUnit cu, String fileName) {
        cu.findAll(MethodCallExpr.class).forEach(expr -> {
            if (!expr.getNameAsString().equals("getInstance")) return;

            // Scope must be a known JCA service class
            String scope = expr.getScope()
                .map(s -> s instanceof NameExpr ? ((NameExpr)s).getNameAsString() : s.toString())
                .orElse("");
            if (!JCA_SERVICES.contains(scope)) return;
            if (expr.getArguments().isEmpty()) return;

            expr.getArguments().get(0).ifStringLiteralExpr(algoLit -> {
                String algo  = algoLit.asString().trim();
                String algoU = algo.toUpperCase();
                int    line  = expr.getBegin().map(p -> p.line).orElse(0);

                // ECB mode
                if (algoU.contains("/ECB/") || algoU.equals("ECB")) {
                    findings.add(new Finding(
                        "INSECURE_CIPHER_MODE_ECB", fileName, line,
                        scope + ".getInstance(\"" + algo + "\") — ECB mode is insecure. " +
                        "Identical plaintext => identical ciphertext. Replace with AES/GCM/NoPadding. " +
                        "CBOMkit detects this (raw JCA call).",
                        "L4-RawJCA", "CRITICAL", "AES-ECB"
                    ));
                    return;
                }

                // Classify against known table
                String status = null; String matched = null;
                for (Map.Entry<String, String> e : QUANTUM_STATUS.entrySet()) {
                    String key = e.getKey().toUpperCase();
                    if (algoU.equals(key) || algoU.startsWith(key + "/")
                        || algoU.startsWith(key + "-") || algoU.contains("WITH" + key)) {
                        status = e.getValue(); matched = e.getKey(); break;
                    }
                }

                String cbomkitNote = "CBOMkit detects this (raw JCA call).";

                if (status == null) {
                    findings.add(new Finding(
                        "CRYPTOGRAPHIC_ASSET_DETECTED", fileName, line,
                        scope + ".getInstance(\"" + algo + "\") — unclassified crypto asset. " + cbomkitNote,
                        "L4-RawJCA", "INFO", algo
                    ));
                    return;
                }

                String detail = scope + ".getInstance(\"" + algo + "\"). " +
                    BREAK_REASON.getOrDefault(matched, "") + ". " +
                    "Replace: " + PQ_REPLACEMENT.getOrDefault(matched, "See NIST PQC") + ". " + cbomkitNote;

                switch (status) {
                    case "notQuantumSafe":
                        findings.add(new Finding("QUANTUM_VULNERABLE_JCA_ALGORITHM",
                            fileName, line, detail, "L4-RawJCA", "CRITICAL", matched));
                        break;
                    case "classicallyBroken":
                        findings.add(new Finding("CLASSICALLY_BROKEN_JCA_ALGORITHM",
                            fileName, line, detail, "L4-RawJCA", "HIGH", matched));
                        break;
                    case "quantumSafe":
                        if ("AES".equals(matched) && algoU.contains("128")) {
                            findings.add(new Finding("WEAK_AES_KEY_SIZE", fileName, line,
                                scope + ".getInstance(\"" + algo + "\") — AES-128. " +
                                "Grover's reduces post-quantum security to 64 bits. Upgrade to AES-256. " + cbomkitNote,
                                "L4-RawJCA", "MEDIUM", "AES-128"));
                        } else {
                            findings.add(new Finding("CRYPTOGRAPHIC_ASSET_INVENTORY", fileName, line,
                                scope + ".getInstance(\"" + algo + "\") — " + matched +
                                " is quantum-safe. Recorded for CBOM inventory. " + cbomkitNote,
                                "L4-RawJCA", "INFO", matched));
                        }
                        break;
                }
            });
        });
    }

    /**
     * Rule 4b — SecretKeySpec constructor — CBOMkit detects these.
     * new SecretKeySpec(bytes, "DES"), new DESedeKeySpec(bytes)
     */
    private void checkSecretKeySpec(CompilationUnit cu, String fileName) {
        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {
            String typeName = expr.getTypeAsString();
            int line = expr.getBegin().map(p -> p.line).orElse(0);

            if (typeName.equals("DESedeKeySpec") || typeName.equals("DESKeySpec")) {
                String algo = typeName.equals("DESedeKeySpec") ? "3DES" : "DES";
                findings.add(new Finding("CLASSICALLY_BROKEN_JCA_ALGORITHM", fileName, line,
                    "new " + typeName + "() — " + algo + " key. " +
                    BREAK_REASON.getOrDefault(algo, "Broken") + ". Replace: AES-256-GCM. " +
                    "CBOMkit detects this.",
                    "L4-RawJCA", "HIGH", algo));
                return;
            }

            if (!typeName.equals("SecretKeySpec")) return;
            if (expr.getArguments().size() < 2) return;

            expr.getArguments().get(1).ifStringLiteralExpr(algoLit -> {
                String algo  = algoLit.asString().trim();
                String algoU = algo.toUpperCase();
                String status = null; String matched = null;

                for (Map.Entry<String, String> e : QUANTUM_STATUS.entrySet()) {
                    String key = e.getKey().toUpperCase();
                    if (algoU.equals(key) || algoU.startsWith(key+"/") || algoU.startsWith(key+"-")) {
                        status = e.getValue(); matched = e.getKey(); break;
                    }
                }
                if (status == null) return;

                String detail = "new SecretKeySpec(key, \"" + algo + "\"). " +
                    BREAK_REASON.getOrDefault(matched, "") + ". Replace: " +
                    PQ_REPLACEMENT.getOrDefault(matched, "See NIST PQC") + ". CBOMkit detects this.";

                switch (status) {
                    case "notQuantumSafe":
                        findings.add(new Finding("QUANTUM_VULNERABLE_JCA_ALGORITHM",
                            fileName, line, detail, "L4-RawJCA", "CRITICAL", matched)); break;
                    case "classicallyBroken":
                        findings.add(new Finding("CLASSICALLY_BROKEN_JCA_ALGORITHM",
                            fileName, line, detail, "L4-RawJCA", "HIGH", matched)); break;
                    case "quantumSafe":
                        findings.add(new Finding("CRYPTOGRAPHIC_ASSET_INVENTORY", fileName, line,
                            "new SecretKeySpec(key, \"" + algo + "\") — quantum-safe. " +
                            "CBOMkit detects this.", "L4-RawJCA", "INFO", matched)); break;
                }
            });
        });
    }

    /**
     * Rule 4c — Weak algorithm string literals (not inside getInstance).
     * Catches: String algo = "SHA-1"; signWith(key, "RS256"); etc.
     * Only reports classicallyBroken and notQuantumSafe (quantumSafe strings are too noisy).
     */
    private void checkWeakAlgorithmStrings(CompilationUnit cu, String fileName) {
        cu.findAll(StringLiteralExpr.class).forEach(str -> {
            String val  = str.asString().trim();
            String valU = val.toUpperCase();
            int    line = str.getBegin().map(p -> p.line).orElse(0);
            if (val.length() < 2 || val.length() > 40) return;

            // Skip if parent is already a getInstance() call — handled by Rule 4a
            if (str.getParentNode().isPresent()) {
                var parent = str.getParentNode().get();
                if (parent instanceof MethodCallExpr &&
                    ((MethodCallExpr)parent).getNameAsString().equals("getInstance")) return;
            }

            if (valU.contains("/ECB/") || valU.equals("ECB")) {
                findings.add(new Finding("INSECURE_CIPHER_MODE_ECB", fileName, line,
                    "Algorithm string \"" + val + "\" — ECB mode. Replace with AES/GCM/NoPadding.",
                    "L4-RawJCA", "CRITICAL", "AES-ECB"));
                return;
            }

            for (Map.Entry<String, String> e : QUANTUM_STATUS.entrySet()) {
                String algo = e.getKey(); String status = e.getValue();
                String algoU = algo.toUpperCase();
                boolean matches = valU.equals(algoU) || valU.startsWith(algoU + "/")
                    || valU.startsWith(algoU + "-") || valU.startsWith("HMACWITH" + algoU)
                    || valU.contains("WITH" + algoU);
                if (!matches) continue;
                if (status.equals("notQuantumSafe")) {
                    findings.add(new Finding("QUANTUM_VULNERABLE_ALGORITHM_STRING", fileName, line,
                        "Algorithm string \"" + val + "\" — quantum-vulnerable. " +
                        BREAK_REASON.getOrDefault(algo, "Broken by Shor's") + ". " +
                        "Replace: " + PQ_REPLACEMENT.getOrDefault(algo, "See NIST PQC"),
                        "L4-RawJCA", "CRITICAL", algo));
                } else if (status.equals("classicallyBroken")) {
                    findings.add(new Finding("CLASSICALLY_BROKEN_ALGORITHM_STRING", fileName, line,
                        "Algorithm string \"" + val + "\" — classically broken. " +
                        BREAK_REASON.getOrDefault(algo, "Known broken") + ". " +
                        "Replace: " + PQ_REPLACEMENT.getOrDefault(algo, "SHA-256 or AES-256-GCM"),
                        "L4-RawJCA", "HIGH", algo));
                }
                return;
            }
        });
    }

    /**
     * Rule 4c — JJWT SignatureAlgorithm enum references.
     * CBOMkit detects these via JJWT-specific rules.
     * e.g. SignatureAlgorithm.HS256, SignatureAlgorithm.RS256
     * These are FieldAccessExpr — NOT StringLiteralExpr.
     */
    private void checkJwtLibraryEnums(CompilationUnit cu, String fileName) {
        cu.findAll(FieldAccessExpr.class).forEach(expr -> {
            String scope = expr.getScope().toString();
            String name  = expr.getNameAsString();
            int    line  = expr.getBegin().map(p -> p.line).orElse(0);
            if (!scope.equals("SignatureAlgorithm") &&
                !scope.equals("io.jsonwebtoken.SignatureAlgorithm")) return;

            String cbomkitNote = "CBOMkit detects this via JJWT-specific rules.";

            if (name.startsWith("RS") || name.startsWith("PS")) {
                findings.add(new Finding("QUANTUM_VULNERABLE_JWT_ALGORITHM", fileName, line,
                    "JJWT SignatureAlgorithm." + name + " — RSA-based JWT. " +
                    BREAK_REASON.getOrDefault("RSA", "Shor's breaks RSA") + ". " +
                    "Replace: ML-DSA (NIST FIPS 204). " + cbomkitNote,
                    "L4-RawJCA", "CRITICAL", "RSA"));
            } else if (name.startsWith("ES")) {
                findings.add(new Finding("QUANTUM_VULNERABLE_JWT_ALGORITHM", fileName, line,
                    "JJWT SignatureAlgorithm." + name + " — ECDSA-based JWT. " +
                    BREAK_REASON.getOrDefault("ECDSA", "Shor's breaks ECDSA") + ". " +
                    "Replace: ML-DSA (NIST FIPS 204). " + cbomkitNote,
                    "L4-RawJCA", "CRITICAL", "ECDSA"));
            } else if (name.startsWith("HS")) {
                String hmac = name.equals("HS256") ? "HMACSHA256" : name.equals("HS384") ? "HMACSHA384" : "HMACSHA512";
                findings.add(new Finding("JWT_HMAC_ALGORITHM_DETECTED", fileName, line,
                    "JJWT SignatureAlgorithm." + name + " — HMAC-SHA JWT. Quantum-safe. " +
                    "Verify secret >= 256 bits. Recorded for CBOM inventory. " + cbomkitNote,
                    "L4-RawJCA", "INFO", hmac));
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // LAYER 1 — Configuration Files (CBOMkit misses these)
    // ═══════════════════════════════════════════════════════════

    private void scanYamlFile(String yamlPath) {
        File f = new File(yamlPath);
        if (!f.exists()) return;
        try {
            List<String> lines = Files.readAllLines(f.toPath());
            for (int i = 0; i < lines.size(); i++) {
                String line  = lines.get(i).trim().toLowerCase();
                int    lineN = i + 1;

                if (line.contains("key-store-type") && line.contains("jks")) {
                    findings.add(new Finding("DEPRECATED_KEYSTORE_TYPE", f.getName(), lineN,
                        "JKS keystore deprecated since Java 9. Migrate to PKCS12. " +
                        "CBOMkit misses this (YAML not parsed by CBOMkit).",
                        "L1-ConfigFile", "MEDIUM", "JKS"));
                }

                if (line.contains("secret") && line.contains(":") && !line.startsWith("#")) {
                    String[] parts = line.split(":", 2);
                    if (parts.length > 1) {
                        String val = parts[1].trim().replaceAll("[\"']", "");
                        if (!val.isEmpty() && !val.startsWith("$") && !val.startsWith("@")
                            && val.length() < 32) {
                            findings.add(new Finding("WEAK_SECRET_IN_CONFIG", f.getName(), lineN,
                                "Short secret (length=" + val.length() + ", min=32). " +
                                "Must be >= 256 bits. Store in secrets manager, not config. " +
                                "CBOMkit misses this (YAML not parsed by CBOMkit).",
                                "L1-ConfigFile", "CRITICAL", "HMACSHA256"));
                        }
                    }
                }

                if (line.contains("protocol") && (line.contains(": tls") || line.contains("=tls"))
                    && !line.contains("tlsv1.3") && !line.contains("tls1.3")) {
                    findings.add(new Finding("TLS_VERSION_NOT_PINNED", f.getName(), lineN,
                        "TLS not pinned to TLSv1.3. Set server.ssl.protocol=TLSv1.3. " +
                        "CBOMkit misses this (YAML not parsed by CBOMkit).",
                        "L1-ConfigFile", "MEDIUM", "TLS"));
                }
            }
        } catch (Exception e) {
            System.err.println("Could not read YAML: " + e.getMessage());
        }
    }

    private void scanPomFile(String pomPath) {
        File f = new File(pomPath);
        if (!f.exists()) return;
        try {
            String content = new String(Files.readAllBytes(f.toPath()));
            if (content.contains("bcprov-jdk15on")) {
                findings.add(new Finding("LEGACY_BOUNCY_CASTLE", "pom.xml", 0,
                    "Legacy BouncyCastle 'bcprov-jdk15on' (Java 1.5 target). Migrate to 'bcprov-jdk18on'. " +
                    "CBOMkit misses this (pom.xml not scanned by CBOMkit).",
                    "L1-MavenDependency", "MEDIUM", "BouncyCastle"));
            }
            if (content.contains("nimbus-jose-jwt")) {
                findings.add(new Finding("NIMBUS_JOSE_JWT_PRESENT", "pom.xml", 0,
                    "nimbus-jose-jwt detected. Verify version >= 10.0.1 (CVE-2025-53864). " +
                    "CBOMkit misses this (pom.xml not scanned by CBOMkit).",
                    "L1-MavenDependency", "INFO", "HMAC"));
            }
            if (content.contains("spring-security-oauth2") && content.contains("2.3.")) {
                findings.add(new Finding("LEGACY_SPRING_SECURITY_OAUTH2", "pom.xml", 0,
                    "Legacy spring-security-oauth2 2.3.x (EOL 2022). Migrate to Spring Authorization Server. " +
                    "CBOMkit misses this (pom.xml not scanned by CBOMkit).",
                    "L1-MavenDependency", "HIGH", "OAuth2"));
            }
        } catch (Exception e) {
            System.err.println("Could not read pom.xml: " + e.getMessage());
        }
    }

    // ── Print human-readable report ────────────────────────────────────────────
    private void printReport() {
        System.out.println("\n══════════════════════════════════════════════");
        System.out.println(" SCAN RESULTS — " + findings.size() + " findings");
        System.out.println("══════════════════════════════════════════════\n");

        String[] layers = {"L1-ConfigFile","L1-MavenDependency","L2-JPAConverter","L3-SpringSecurityBean","L4-RawJCA"};
        for (String layer : layers) {
            List<Finding> lf = findings.stream().filter(f -> f.layer.equals(layer)).toList();
            if (!lf.isEmpty()) {
                System.out.println("── " + layer + " ──────────────────────");
                lf.forEach(f -> System.out.println("  " + f));
                System.out.println();
            }
        }

        long crit   = findings.stream().filter(f -> "CRITICAL".equals(f.severity)).count();
        long high   = findings.stream().filter(f -> "HIGH".equals(f.severity)).count();
        long medium = findings.stream().filter(f -> "MEDIUM".equals(f.severity)).count();
        long info   = findings.stream().filter(f -> "INFO".equals(f.severity)).count();
        long qVuln  = findings.stream().filter(f -> "notQuantumSafe".equals(f.quantumStatus)).count();
        long cBrk   = findings.stream().filter(f -> "classicallyBroken".equals(f.quantumStatus)).count();
        long miss   = findings.stream().filter(f -> !f.layer.equals("L4-RawJCA")).count();

        System.out.println("══════════════════════════════════════════════");
        System.out.printf(" CRITICAL: %d  HIGH: %d  MEDIUM: %d  INFO: %d%n", crit, high, medium, info);
        System.out.printf(" Quantum-vulnerable (Shor's): %d%n", qVuln);
        System.out.printf(" Classically broken: %d%n", cBrk);
        System.out.printf(" CBOMkit would miss: %d of %d (%.0f%%)%n",
            miss, findings.size(), findings.isEmpty() ? 0.0 : miss * 100.0 / findings.size());
        System.out.println("══════════════════════════════════════════════");
    }

    /**
     * Returns true only if CBOMkit would actually detect this finding.
     *
     * CBOMkit detects findings when:
     *   - Layer is L4-RawJCA (CBOMkit only scans raw JCA calls)
     *   - Severity is not INFO (CBOMkit only reports vulnerabilities, not inventory)
     *   - Detection rule is a genuine JCA getInstance() or constructor call
     *
     * CBOMkit does NOT detect:
     *   - CLASSICALLY_BROKEN_ALGORITHM_STRING  — plain string literal, not instanceof call
     *   - QUANTUM_VULNERABLE_ALGORITHM_STRING  — plain string literal
     *   - JWT_HMAC_ALGORITHM_DETECTED          — JJWT enum FieldAccessExpr
     *   - QUANTUM_VULNERABLE_JWT_ALGORITHM     — JJWT enum FieldAccessExpr
     *   - CRYPTOGRAPHIC_ASSET_DETECTED         — unclassified/INFO
     *   - CRYPTOGRAPHIC_ASSET_INVENTORY        — INFO severity
     *   - Anything at L1/L2/L3
     */
    private boolean isCBOMkitDetectable(Finding f) {
        // Must be at Layer 4
        if (!f.layer.equals("L4-RawJCA")) return false;
        // Must be a vulnerability (not INFO inventory)
        if (f.severity.equals("INFO")) return false;
        // Must be a genuine JCA instanceof/constructor rule — not string literal or enum
        switch (f.rule) {
            case "QUANTUM_VULNERABLE_JCA_ALGORITHM":      // instanceof call ✅
            case "CLASSICALLY_BROKEN_JCA_ALGORITHM":      // instanceof call ✅
            case "INSECURE_CIPHER_MODE_ECB":              // instanceof call ✅
            case "WEAK_AES_KEY_SIZE":                     // instanceof call ✅
                return true;
            // String literal rules — CBOMkit does NOT detect these
            case "CLASSICALLY_BROKEN_ALGORITHM_STRING":   // plain string "md5" ❌
            case "QUANTUM_VULNERABLE_ALGORITHM_STRING":   // plain string "RSA" ❌
            // JJWT enum rules — CBOMkit has own JJWT rules but via different AST path
            case "QUANTUM_VULNERABLE_JWT_ALGORITHM":      // SignatureAlgorithm.RS256 ❌
            case "JWT_HMAC_ALGORITHM_DETECTED":           // SignatureAlgorithm.HS256 ❌
            // Inventory/unknown
            case "CRYPTOGRAPHIC_ASSET_DETECTED":          // unclassified ❌
            case "CRYPTOGRAPHIC_ASSET_INVENTORY":         // INFO ❌
            default:
                return false;
        }
    }

    // ── Write CycloneDX 1.6 CBOM JSON ─────────────────────────────────────────
    private void writeCBOM(String outputPath) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"bomFormat\": \"CycloneDX\",\n");
        sb.append("  \"specVersion\": \"1.6\",\n");
        sb.append("  \"serialNumber\": \"urn:uuid:").append(UUID.randomUUID()).append("\",\n");
        sb.append("  \"version\": 1,\n");
        sb.append("  \"metadata\": {\n");
        sb.append("    \"timestamp\": \"").append(Instant.now()).append("\",\n");
        sb.append("    \"tools\": [{\n");
        sb.append("      \"vendor\": \"IIT Jodhpur\",\n");
        sb.append("      \"name\": \"SpringCryptoScanner\",\n");
        sb.append("      \"version\": \"2.0\",\n");
        sb.append("      \"description\": \"CBOMkit L4 coverage + Spring L3/L2/L1 coverage\"\n");
        sb.append("    }],\n");
        sb.append("    \"component\": {\"type\": \"application\", \"name\": \"")
          .append(escapeJson(projectName)).append("\", \"version\": \"1.0\"},\n");
        sb.append("    \"properties\": [\n");
        if (!sourceUrl.isEmpty()) {
            sb.append("      {\"name\": \"gitUrl\",    \"value\": \"").append(escapeJson(sourceUrl)).append("\"},\n");
            sb.append("      {\"name\": \"commit\",    \"value\": \"").append(escapeJson(sourceCommit)).append("\"},\n");
            sb.append("      {\"name\": \"revision\",  \"value\": \"").append(escapeJson(sourceBranch)).append("\"},\n");
        }
        sb.append("      {\"name\": \"scannedBy\",    \"value\": \"SpringCryptoScanner v2.0 — IIT Jodhpur\"},\n");
        sb.append("      {\"name\": \"thesisAuthor\", \"value\": \"Kandasamy | M25AID042\"}\n");
        sb.append("    ]\n");
        sb.append("  },\n");

        sb.append("  \"components\": [\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            sb.append("    {\n");
            sb.append("      \"type\": \"cryptographic-asset\",\n");
            sb.append("      \"bom-ref\": \"crypto/").append(f.layer).append("/")
              .append(f.algorithm.replaceAll("[^a-zA-Z0-9]","_")).append("-").append(i).append("\",\n");
            sb.append("      \"name\": \"").append(escapeJson(f.algorithm)).append("\",\n");
            sb.append("      \"description\": \"").append(escapeJson(f.detail)).append("\",\n");
            sb.append("      \"cryptoProperties\": {\n");
            sb.append("        \"assetType\": \"algorithm\",\n");
            sb.append("        \"algorithmProperties\": {\n");
            sb.append("          \"primitive\": \"").append(escapeJson(f.primitive)).append("\",\n");
            sb.append("          \"executionEnvironment\": \"software-plain-ram\",\n");
            sb.append("          \"nistQuantumSecurityLevel\": ").append(mapToNistLevel(f.quantumStatus)).append("\n");
            sb.append("        },\n");
            sb.append("        \"oid\": \"\"\n");
            sb.append("      },\n");
            sb.append("      \"properties\": [\n");
            sb.append("        {\"name\": \"spring-layer\",    \"value\": \"").append(escapeJson(f.layer)).append("\"},\n");
            sb.append("        {\"name\": \"detection-rule\",  \"value\": \"").append(escapeJson(f.rule)).append("\"},\n");
            sb.append("        {\"name\": \"severity\",        \"value\": \"").append(escapeJson(f.severity)).append("\"},\n");
            sb.append("        {\"name\": \"quantum-status\",  \"value\": \"").append(escapeJson(f.quantumStatus)).append("\"},\n");
            sb.append("        {\"name\": \"source-file\",     \"value\": \"").append(escapeJson(f.file)).append("\"},\n");
            sb.append("        {\"name\": \"source-line\",     \"value\": \"").append(f.line).append("\"},\n");
            sb.append("        {\"name\": \"pq-replacement\",  \"value\": \"").append(escapeJson(f.replacement)).append("\"},\n");
            sb.append("        {\"name\": \"cbomkit-detects\", \"value\": \"")
              // CBOMkit detects a finding ONLY when ALL of these are true:
              //   1. Layer is L4-RawJCA (raw JCA call)
              //   2. Severity is not INFO (vulnerable algorithm, not inventory)
              //   3. Detection rule is a genuine JCA getInstance() or constructor call
              //      NOT a plain string literal or JJWT enum (CBOMkit doesn't match those)
              .append(isCBOMkitDetectable(f) ? "true" : "false")
              .append("\"}\n");
            sb.append("      ]\n");
            sb.append("    }");
            if (i < findings.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");
        sb.append("  \"vulnerabilities\": [],\n");

        long miss = findings.stream().filter(f -> !f.layer.equals("L4-RawJCA")).count();
        sb.append("  \"extensions\": [{\n");
        sb.append("    \"namespace\": \"https://github.com/KandasamyShunmugaraj/spring-crypto-scanner\",\n");
        sb.append("    \"springCryptoScannerSummary\": {\n");
        sb.append("      \"totalFindings\": ").append(findings.size()).append(",\n");
        sb.append("      \"layer1Findings\": ").append(findings.stream().filter(f->f.layer.startsWith("L1")).count()).append(",\n");
        sb.append("      \"layer2Findings\": ").append(findings.stream().filter(f->f.layer.startsWith("L2")).count()).append(",\n");
        sb.append("      \"layer3Findings\": ").append(findings.stream().filter(f->f.layer.startsWith("L3")).count()).append(",\n");
        sb.append("      \"layer4Findings\": ").append(findings.stream().filter(f->f.layer.startsWith("L4")).count()).append(",\n");
        sb.append("      \"quantumVulnerable\": ").append(findings.stream().filter(f->"notQuantumSafe".equals(f.quantumStatus)).count()).append(",\n");
        sb.append("      \"classicallyBroken\": ").append(findings.stream().filter(f->"classicallyBroken".equals(f.quantumStatus)).count()).append(",\n");
        sb.append("      \"cbomkitWouldMiss\": ").append(miss).append(",\n");
        sb.append("      \"note\": \"Layer 4 findings match CBOMkit JCA detection. Layers 1-3 are invisible to CBOMkit.\"\n");
        sb.append("    }\n  }]\n}\n");

        try (FileWriter fw = new FileWriter(outputPath)) { fw.write(sb.toString()); }
    }

    private String mapToNistLevel(String status) {
        if ("notQuantumSafe".equals(status) || "classicallyBroken".equals(status)) return "0";
        if ("quantumSafe".equals(status)) return "5";
        return "0";
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\","\\\\").replace("\"","\\\"")
                .replace("\n","\\n").replace("\r","\\r").replace("\t","\\t");
    }

    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0]
            : System.getProperty("user.home") + "/thesis/crypto-gap-test";
        new SpringCryptoScanner(path).scan();
    }
}
