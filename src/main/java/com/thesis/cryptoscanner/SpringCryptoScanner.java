package com.thesis.cryptoscanner;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ClassExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.IntegerLiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * SpringCryptoScanner v2.1
 *
 * v2.1 corrections (October 2026) — see CHANGELOG.md for evidence per item:
 *   1. Parser now accepts modern Java (records, text blocks, sealed types). v2.0 silently
 *      skipped every file it could not parse (60 files across the evaluation corpus).
 *   2. Test code excluded consistently (src/test, src/integTest, *Test/*Tests/*IT/*ITest.java).
 *      Every finding is tagged with its code context: main | sample | docs.
 *   3. L3 MISSING_JWT_ALGORITHM_WHITELIST removed — false positive. Spring Security's
 *      NimbusJwtDecoder.withPublicKey()/withSecretKey() builders pin a single algorithm via
 *      SingleKeyJWSKeySelector and have no setJwsAlgorithms(). Replaced by the inventory rule
 *      JWT_DECODER_SIGNATURE_ALGORITHM, which records the algorithm actually configured.
 *   4. L1 config secrets: real .properties/.yml parsing (v2.0 split on ':' and measured the
 *      text after the ':' inside ${ENV:default}). Placeholders are skipped; only crypto-key
 *      settings (jwt/signing/hmac/encryption keys) are checked; comments are ignored.
 *   5. New L4 rule HARDCODED_CRYPTO_KEY: string literals that flow into a signing or
 *      encryption key sink (signWith, hmacShaKeyFor, SecretKeySpec, ...).
 *   6. JWT algorithm enums attributed to the right library (JJWT vs Spring Security JOSE vs
 *      Nimbus). Spring Security JOSE settings are framework-layer (L3).
 *   7. L2 @Convert: the converter class is resolved and reported only if it uses crypto.
 *   8. L3 extended to Spring Security password encoders and Encryptors.
 *   9. Algorithm strings configured inside a Spring @Bean method are reported at L3.
 *  10. Config and build files scanned in every module, not only the repository root.
 *  11. "cbomkit-expected" now means: produced by a JCA call CBOMkit's rules cover. Whether
 *      CBOMkit actually reports it is measured separately (see scripts/compare.py).
 *
 * Original v2.0 description:
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
        QUANTUM_STATUS.put("MD4",       "classicallyBroken");
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
        PRIMITIVE_TYPE.put("MD4",      "hash");
        PRIMITIVE_TYPE.put("SHA-1",    "hash");
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
        /** main | sample | docs — where in the repository the finding sits. */
        public String context = "main";
        /** true when the finding comes from a JCA call that CBOMkit's rules are designed to detect. */
        public boolean cbomkitExpected = false;

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
            return String.format("[%s] [%s] [%s] %s @ %s:%d — %s [quantum: %s]",
                severity, layer, context, rule, file, line, detail, quantumStatus);
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

    // ── Scan scope ─────────────────────────────────────────────────────────────
    /** Test code is out of scope (same as CBOMkit's default exclusions, plus Gradle test sets). */
    private static final Pattern TEST_PATH = Pattern.compile(
        "(^|/)src/(test|integTest|integrationTest|testFixtures|it)/|(^|/)test/java/"
        + "|(Test|Tests|IT|ITest|TestCase)\\.java$");
    private static final Pattern DOCS_PATH   = Pattern.compile("(^|/)(docs?|documentation)/");
    private static final Pattern SAMPLE_PATH = Pattern.compile("(^|/)(samples?|examples?|demos?)[^/]*/");

    static boolean isTestPath(String rel)  { return TEST_PATH.matcher(rel.replace('\\','/')).find(); }
    static String contextOf(String rel) {
        String r = rel.replace('\\', '/');
        int src = r.indexOf("src/");               // judge by module folders only, not Java packages
        if (src >= 0) r = r.substring(0, src);
        if (DOCS_PATH.matcher(r).find())   return "docs";
        if (SAMPLE_PATH.matcher(r).find()) return "sample";
        return "main";
    }

    private final JavaParser parser = new JavaParser(
        new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.BLEEDING_EDGE));
    private final List<String> parseFailures = new ArrayList<>();
    public  List<String> getParseFailures() { return parseFailures; }
    private int javaFilesScanned = 0;
    public  int getJavaFilesScanned() { return javaFilesScanned; }

    /** simple class name -> parsed compilation unit, used to resolve @Convert converters. */
    private final Map<String, CompilationUnit> classIndex = new HashMap<>();

    private String rel(Path p) {
        try { return Paths.get(projectPath).relativize(p).toString().replace('\\', '/'); }
        catch (Exception e) { return p.getFileName().toString(); }
    }

    // ── Entry point ────────────────────────────────────────────────────────────
    public void scan() throws Exception {
        System.out.println("==============================================");
        System.out.println(" Spring Crypto Scanner v2.1");
        System.out.println(" Scanning: " + projectPath);
        System.out.println("==============================================\n");

        // Pass 1: parse every non-test Java file once
        Map<String, CompilationUnit> units = new java.util.TreeMap<>();
        List<Path> configFiles = new ArrayList<>();
        List<Path> buildFiles  = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(Paths.get(projectPath))) {
            for (Path p : (Iterable<Path>) paths::iterator) {
                String r = rel(p);
                if (r.startsWith(".git/") || r.contains("/.git/") || r.contains("node_modules/")
                    || r.contains("/build/") || r.startsWith("build/") || r.contains("/target/") || r.startsWith("target/")) continue;
                if (!Files.isRegularFile(p) || isTestPath(r)) continue;
                String fn = p.getFileName().toString();
                if (fn.endsWith(".java")) {
                    if (fn.equals("SpringCryptoScanner.java")) continue;
                    ParseResult<CompilationUnit> res;
                    try { res = parser.parse(p); }
                    catch (Exception e) { parseFailures.add(r); continue; }
                    if (!res.isSuccessful() || res.getResult().isEmpty()) { parseFailures.add(r); continue; }
                    CompilationUnit cu = res.getResult().get();
                    units.put(r, cu);
                    cu.getPrimaryTypeName().ifPresent(n -> classIndex.putIfAbsent(n, cu));
                    cu.getTypes().forEach(t -> classIndex.putIfAbsent(t.getNameAsString(), cu));
                } else if (fn.matches("(application|bootstrap)[-\\w]*\\.(ya?ml|properties)")
                           && r.contains("resources/")) {
                    configFiles.add(p);
                } else if (fn.equals("pom.xml") || fn.endsWith(".gradle") || fn.endsWith(".gradle.kts")) {
                    buildFiles.add(p);
                }
            }
        }

        // Pass 2: rules
        for (Map.Entry<String, CompilationUnit> e : units.entrySet()) {
            javaFilesScanned++;
            scanJavaFile(e.getValue(), e.getKey());
        }
        for (Path c : configFiles) scanConfigFile(c);
        for (Path b : buildFiles)  scanBuildFile(b);

        for (Finding f : findings) f.context = contextOf(f.file);

        if (!parseFailures.isEmpty()) {
            System.out.println(" WARNING: " + parseFailures.size() + " Java file(s) could not be parsed and were NOT scanned:");
            parseFailures.forEach(pf -> System.out.println("   - " + pf));
        }
        printReport();

        String cbomPath = projectPath + "/cbom-springscanner.json";
        writeCBOM(cbomPath);
        System.out.println("\n CBOM JSON written to: " + cbomPath);
    }

    private void scanJavaFile(CompilationUnit cu, String name) {
        // Layer 3
        checkBCrypt(cu, name);
        checkSpringPasswordEncoders(cu, name);
        checkJwtDecoder(cu, name);
        // Layer 2
        checkConvertAnnotation(cu, name);
        // Layer 4 — JCA calls (what CBOMkit's rules cover) + extensions
        checkJcaGetInstance(cu, name);
        checkSecretKeySpec(cu, name);
        checkWeakAlgorithmStrings(cu, name);
        checkJwtLibraryEnums(cu, name);
        checkHardcodedCryptoKeys(cu, name);
    }

    // ── AST helpers ────────────────────────────────────────────────────────────
    private static int lineOf(Node n) { return n.getBegin().map(p -> p.line).orElse(0); }

    /** True when the node sits inside a method annotated with Spring's @Bean. */
    private static boolean insideBeanMethod(Node n) {
        Optional<MethodDeclaration> m = n.findAncestor(MethodDeclaration.class);
        return m.isPresent() && m.get().getAnnotations().stream()
            .anyMatch(a -> a.getNameAsString().equals("Bean"));
    }

    private static boolean importsPackage(CompilationUnit cu, String prefix) {
        return cu.getImports().stream().anyMatch(i -> i.getNameAsString().startsWith(prefix));
    }

    /** Adds a finding produced by a JCA call that CBOMkit's rules are designed to report. */
    private void addJca(Finding f) { f.cbomkitExpected = true; findings.add(f); }

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

    /**
     * Severity given to quantum-vulnerable public-key algorithms (RSA, EC, DSA, DH).
     * v2.0 policy kept unchanged; change here to apply a different policy everywhere.
     */
    static final String SEV_QUANTUM_VULNERABLE = "CRITICAL";

    private static final Pattern JWS_NAME = Pattern.compile("\\b(RS|PS|ES|HS)(256|384|512)\\b");

    /** Maps a JOSE algorithm name (RS256, ES384, HS512 ...) to this scanner's algorithm keys. */
    private static String joseToAlgorithm(String jws) {
        if (jws.startsWith("RS") || jws.startsWith("PS")) return "RSA";
        if (jws.startsWith("ES")) return "ECDSA";
        return "HMACSHA" + jws.substring(2);
    }

    /** Resolves an algorithm argument such as SignatureAlgorithm.RS512 or a constant holding it. */
    private static Optional<String> resolveJws(Expression arg, CompilationUnit cu) {
        Matcher m = JWS_NAME.matcher(arg.toString());
        if (m.find()) return Optional.of(m.group());
        if (arg.isNameExpr()) {
            String n = arg.asNameExpr().getNameAsString();
            for (VariableDeclarator v : cu.findAll(VariableDeclarator.class)) {
                if (v.getNameAsString().equals(n) && v.getInitializer().isPresent()) {
                    Matcher mi = JWS_NAME.matcher(v.getInitializer().get().toString());
                    if (mi.find()) return Optional.of(mi.group());
                }
            }
        }
        return Optional.empty();
    }

    /**
     * L3 — JWT signature verification configured through Spring Security's NimbusJwtDecoder builders.
     *
     * Replaces v2.0's MISSING_JWT_ALGORITHM_WHITELIST, which was a false positive:
     * withPublicKey()/withSecretKey() build a SingleKeyJWSKeySelector that accepts exactly one
     * algorithm (RS256 / HS256 unless signatureAlgorithm()/macAlgorithm() is called), so
     * algorithm confusion is not possible, and setJwsAlgorithms() does not exist on these builders.
     * What IS useful for a CBOM is the algorithm itself, which CBOMkit cannot see (no JCA call).
     */
    private void checkJwtDecoder(CompilationUnit cu, String fileName) {
        cu.findAll(MethodCallExpr.class).forEach(expr -> {
            String name = expr.getNameAsString();
            if (!name.equals("withSecretKey") && !name.equals("withPublicKey") && !name.equals("withJwkSetUri")) return;
            String scope = expr.getScope().map(Object::toString).orElse("");
            if (!scope.endsWith("NimbusJwtDecoder") && !scope.endsWith("NimbusReactiveJwtDecoder")) return;

            // Walk up the fluent chain: withPublicKey(k).signatureAlgorithm(X).build()
            String jws = null;
            boolean explicitUnresolved = false;
            Node cur = expr;
            while (cur.getParentNode().isPresent() && cur.getParentNode().get() instanceof MethodCallExpr) {
                MethodCallExpr parent = (MethodCallExpr) cur.getParentNode().get();
                if (parent.getScope().isEmpty() || parent.getScope().get() != cur) break;
                String pn = parent.getNameAsString();
                if ((pn.equals("signatureAlgorithm") || pn.equals("macAlgorithm") || pn.equals("jwsAlgorithm"))
                    && !parent.getArguments().isEmpty()) {
                    Optional<String> r = resolveJws(parent.getArgument(0), cu);
                    if (r.isPresent()) jws = r.get(); else explicitUnresolved = true;
                }
                cur = parent;
            }
            if (jws == null && explicitUnresolved) {
                findings.add(new Finding("JWT_DECODER_SIGNATURE_ALGORITHM", fileName, lineOf(expr),
                    "Spring Security " + scope + "." + name + "() — JWT verification algorithm chosen at runtime ("
                    + "not resolvable statically). Recorded for CBOM inventory. Not visible to CBOMkit.",
                    "L3-SpringSecurityBean", "INFO", "JWS-runtime"));
                return;
            }
            boolean isDefault = jws == null;
            if (isDefault) jws = name.equals("withSecretKey") ? "HS256" : "RS256";

            String algo = joseToAlgorithm(jws);
            boolean pq  = !algo.startsWith("HMAC");
            String detail = "Spring Security " + scope + "." + name + "() verifies JWT signatures with " + jws
                + (isDefault ? " (builder default)" : "") + ". The builder accepts only this one algorithm. "
                + (pq ? BREAK_REASON.getOrDefault(algo, "Quantum-vulnerable") + ". Plan migration to ML-DSA (NIST FIPS 204). "
                      : "HMAC is quantum-safe; verify the key is at least 256 bits. ")
                + "Not visible to CBOMkit (configured through the framework, no JCA call in application code).";
            findings.add(new Finding("JWT_DECODER_SIGNATURE_ALGORITHM", fileName, lineOf(expr), detail,
                "L3-SpringSecurityBean", pq ? SEV_QUANTUM_VULNERABLE : "INFO", algo));
        });
    }

    /**
     * L3 — Spring Security crypto module: password encoders and Encryptors.
     * These are constructed as framework objects (usually in a @Bean), never via JCA getInstance.
     */
    private void checkSpringPasswordEncoders(CompilationUnit cu, String fileName) {
        final String L3 = "L3-SpringSecurityBean";
        final String note = " Not visible to CBOMkit (Spring Security object, not a JCA call).";
        cu.findAll(ObjectCreationExpr.class).forEach(expr -> {
            String t = expr.getType().getNameAsString();
            int line = lineOf(expr);
            switch (t) {
                case "BCryptPasswordEncoder":
                    boolean weak = !expr.getArguments().isEmpty() && expr.getArgument(0).isIntegerLiteralExpr()
                        && Integer.parseInt(expr.getArgument(0).asIntegerLiteralExpr().getValue()) < 10;
                    if (!weak) findings.add(new Finding("PASSWORD_HASHING_ALGORITHM", fileName, line,
                        "BCryptPasswordEncoder — password hashing with bcrypt (cost >= 10)." + note, L3, "INFO", "BCrypt"));
                    break; // weak cost handled by checkBCrypt
                case "Pbkdf2PasswordEncoder":
                case "SCryptPasswordEncoder":
                case "Argon2PasswordEncoder": {
                    String a = t.replace("PasswordEncoder", "").toUpperCase();
                    findings.add(new Finding("PASSWORD_HASHING_ALGORITHM", fileName, line,
                        t + " — password hashing with " + a + "." + note, L3, "INFO", a));
                    break;
                }
                case "MessageDigestPasswordEncoder": {
                    String a = expr.getArguments().isEmpty() || !expr.getArgument(0).isStringLiteralExpr()
                        ? "unknown" : expr.getArgument(0).asStringLiteralExpr().asString().toUpperCase();
                    findings.add(new Finding("DEPRECATED_PASSWORD_ENCODER", fileName, line,
                        "MessageDigestPasswordEncoder(" + a + ") — single fast digest for passwords; deprecated by "
                        + "Spring Security. Use bcrypt/Argon2 via DelegatingPasswordEncoder." + note, L3, "HIGH", a));
                    break;
                }
                case "StandardPasswordEncoder":
                    findings.add(new Finding("DEPRECATED_PASSWORD_ENCODER", fileName, line,
                        "StandardPasswordEncoder — SHA-256 with 1024 iterations; deprecated by Spring Security." + note,
                        L3, "HIGH", "SHA-256"));
                    break;
                case "LdapShaPasswordEncoder":
                    findings.add(new Finding("DEPRECATED_PASSWORD_ENCODER", fileName, line,
                        "LdapShaPasswordEncoder — salted SHA-1; deprecated by Spring Security." + note, L3, "HIGH", "SHA-1"));
                    break;
                case "Md4PasswordEncoder":
                    findings.add(new Finding("DEPRECATED_PASSWORD_ENCODER", fileName, line,
                        "Md4PasswordEncoder — MD4; deprecated by Spring Security." + note, L3, "HIGH", "MD4"));
                    break;
                default:
            }
        });
        cu.findAll(MethodCallExpr.class).forEach(expr -> {
            String scope = expr.getScope().map(Object::toString).orElse("");
            String n = expr.getNameAsString();
            int line = lineOf(expr);
            if (scope.endsWith("NoOpPasswordEncoder") && n.equals("getInstance")) {
                findings.add(new Finding("PLAINTEXT_PASSWORD_STORAGE", fileName, line,
                    "NoOpPasswordEncoder — passwords stored in plain text." + note, L3, "CRITICAL", "NONE"));
            } else if (scope.endsWith("PasswordEncoderFactories") && n.equals("createDelegatingPasswordEncoder")) {
                findings.add(new Finding("PASSWORD_HASHING_ALGORITHM", fileName, line,
                    "DelegatingPasswordEncoder — bcrypt by default, algorithm id stored per hash." + note, L3, "INFO", "BCrypt"));
            } else if ((scope.endsWith("Pbkdf2PasswordEncoder") || scope.endsWith("SCryptPasswordEncoder")
                        || scope.endsWith("Argon2PasswordEncoder")) && n.startsWith("defaultsForSpringSecurity")) {
                String a = scope.substring(scope.lastIndexOf('.') + 1).replace("PasswordEncoder", "").toUpperCase();
                findings.add(new Finding("PASSWORD_HASHING_ALGORITHM", fileName, line,
                    scope + "." + n + "() — password hashing with " + a + "." + note, L3, "INFO", a));
            } else if (scope.endsWith("Encryptors")) {
                switch (n) {
                    case "stronger": case "delux":
                        findings.add(new Finding("SPRING_ENCRYPTOR", fileName, line,
                            "Encryptors." + n + "() — AES-256-GCM, PBKDF2-derived key." + note, L3, "INFO", "AES")); break;
                    case "standard": case "text":
                        findings.add(new Finding("SPRING_ENCRYPTOR", fileName, line,
                            "Encryptors." + n + "() — AES-256-CBC without authentication; Spring recommends stronger()/delux()." + note,
                            L3, "MEDIUM", "AES")); break;
                    case "queryableText":
                        findings.add(new Finding("SPRING_ENCRYPTOR", fileName, line,
                            "Encryptors.queryableText() — deterministic AES-CBC with a shared IV; equal plaintexts give equal ciphertexts." + note,
                            L3, "HIGH", "AES")); break;
                    case "noOpText":
                        findings.add(new Finding("SPRING_ENCRYPTOR", fileName, line,
                            "Encryptors.noOpText() — no encryption at all." + note, L3, "CRITICAL", "NONE")); break;
                    default:
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // LAYER 2 — Spring Data @Convert (CBOMkit misses these)
    // ═══════════════════════════════════════════════════════════

    private static final Pattern CRYPTO_IN_CONVERTER = Pattern.compile(
        "\\b(Cipher|SecretKeySpec|Mac|TextEncryptor|BytesEncryptor|Encryptors|StandardPBEStringEncryptor"
        + "|AesBytesEncryptor|KeyGenerator)\\b|\\b(encrypt|decrypt)\\w*\\s*\\(");

    /** Extracts the converter class from @Convert(converter = X.class) or @Convert(X.class). */
    private static Optional<String> converterClass(AnnotationExpr ann) {
        Expression v = null;
        if (ann instanceof SingleMemberAnnotationExpr) v = ((SingleMemberAnnotationExpr) ann).getMemberValue();
        if (ann instanceof NormalAnnotationExpr) {
            v = ((NormalAnnotationExpr) ann).getPairs().stream()
                .filter(p -> p.getNameAsString().equals("converter")).map(p -> p.getValue()).findFirst().orElse(null);
        }
        if (v instanceof ClassExpr) {
            String t = ((ClassExpr) v).getType().asString();
            return Optional.of(t.substring(t.lastIndexOf('.') + 1));
        }
        return Optional.empty();
    }

    /**
     * L2 — JPA @Convert on an entity field whose converter performs cryptography.
     * v2.0 flagged every @Convert (including enum/date/JSON converters). v2.1 resolves the
     * converter class in the project and reports only when it uses crypto; the algorithm is
     * taken from the converter's Cipher.getInstance(...) when present.
     */
    private void checkConvertAnnotation(CompilationUnit cu, String fileName) {
        cu.findAll(FieldDeclaration.class).forEach(field -> {
            field.getAnnotations().forEach(ann -> {
                if (!ann.getNameAsString().equals("Convert")) return;
                String fieldName = field.getVariables().isNonEmpty()
                    ? field.getVariables().get(0).getNameAsString() : "unknown";
                Optional<String> conv = converterClass(ann);
                CompilationUnit convCu = conv.map(classIndex::get).orElse(null);
                if (convCu == null) return;                     // converter not in this project: cannot judge
                String src = convCu.toString();
                if (!CRYPTO_IN_CONVERTER.matcher(src).find()) return;  // not a crypto converter

                String algo = "unknown";
                String severity = "MEDIUM";
                for (MethodCallExpr mc : convCu.findAll(MethodCallExpr.class)) {
                    if (mc.getNameAsString().equals("getInstance") && mc.getScope().map(Object::toString).orElse("").matches("(javax\\.crypto\\.)?Cipher")
                        && !mc.getArguments().isEmpty() && mc.getArgument(0).isStringLiteralExpr()) {
                        String a = mc.getArgument(0).asStringLiteralExpr().asString().toUpperCase();
                        algo = a.contains("/ECB/") || (a.equals("AES")) ? "AES-ECB" : a.split("/")[0];
                        if (algo.equals("AES-ECB")) severity = "HIGH";
                        break;
                    }
                }
                findings.add(new Finding(
                    "FIELD_LEVEL_ENCRYPTION_DETECTED", fileName, lineOf(field),
                    "@Convert(" + conv.get() + ") on field '" + fieldName + "' — JPA field-level encryption"
                    + (algo.equals("unknown") ? "" : " using " + algo + (algo.equals("AES-ECB")
                        ? " (Cipher \"AES\" defaults to ECB)" : "")) + ". "
                    + "The entity field is the asset; the cipher call alone does not say which data it protects. "
                    + "Not visible to CBOMkit as a data-level asset (annotation).",
                    "L2-JPAConverter", severity, algo));
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
            // accept both MessageDigest.getInstance(..) and java.security.MessageDigest.getInstance(..)
            String scopeFull = expr.getScope()
                .map(s -> s instanceof NameExpr ? ((NameExpr)s).getNameAsString() : s.toString())
                .orElse("");
            String scope = scopeFull.substring(scopeFull.lastIndexOf('.') + 1);
            if (!JCA_SERVICES.contains(scope)) return;
            if (expr.getArguments().isEmpty()) return;

            expr.getArguments().get(0).ifStringLiteralExpr(algoLit -> {
                String algo  = algoLit.asString().trim();
                String algoU = algo.toUpperCase();
                int    line  = expr.getBegin().map(p -> p.line).orElse(0);

                // ECB mode — explicit, or implicit: Cipher.getInstance("AES") defaults to AES/ECB/PKCS5Padding
                final boolean implicitEcb = scope.equals("Cipher") && (algoU.equals("AES") || algoU.equals("DESEDE") || algoU.equals("DES"));
                if (algoU.contains("/ECB/") || algoU.equals("ECB") || implicitEcb) {
                    addJca(new Finding(
                        "INSECURE_CIPHER_MODE_ECB", fileName, line,
                        scope + ".getInstance(\"" + algo + "\") — ECB mode" + (implicitEcb ? " (provider default when no mode is given)" : "") + " is insecure. " +
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
                    addJca(new Finding(
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
                        addJca(new Finding("QUANTUM_VULNERABLE_JCA_ALGORITHM",
                            fileName, line, detail, "L4-RawJCA", SEV_QUANTUM_VULNERABLE, matched));
                        break;
                    case "classicallyBroken":
                        addJca(new Finding("CLASSICALLY_BROKEN_JCA_ALGORITHM",
                            fileName, line, detail, "L4-RawJCA", "HIGH", matched));
                        break;
                    case "quantumSafe":
                        if ("AES".equals(matched) && algoU.contains("128")) {
                            addJca(new Finding("WEAK_AES_KEY_SIZE", fileName, line,
                                scope + ".getInstance(\"" + algo + "\") — AES-128. " +
                                "Grover's reduces post-quantum security to 64 bits. Upgrade to AES-256. " + cbomkitNote,
                                "L4-RawJCA", "MEDIUM", "AES-128"));
                        } else {
                            addJca(new Finding("CRYPTOGRAPHIC_ASSET_INVENTORY", fileName, line,
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
                addJca(new Finding("CLASSICALLY_BROKEN_JCA_ALGORITHM", fileName, line,
                    "new " + typeName + "() — " + algo + " key. " +
                    BREAK_REASON.getOrDefault(algo, "Broken") + ". Replace: AES-256-GCM. " +
                    "CBOMkit detects this.",
                    "L4-RawJCA", "HIGH", algo));
                return;
            }

            if (!typeName.equals("SecretKeySpec")) return;
            if (expr.getArguments().size() < 2) return;

            // algorithm is the last argument: SecretKeySpec(key, alg) or SecretKeySpec(key, off, len, alg)
            expr.getArguments().get(expr.getArguments().size() - 1).ifStringLiteralExpr(algoLit -> {
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
                        addJca(new Finding("QUANTUM_VULNERABLE_JCA_ALGORITHM",
                            fileName, line, detail, "L4-RawJCA", SEV_QUANTUM_VULNERABLE, matched)); break;
                    case "classicallyBroken":
                        addJca(new Finding("CLASSICALLY_BROKEN_JCA_ALGORITHM",
                            fileName, line, detail, "L4-RawJCA", "HIGH", matched)); break;
                    case "quantumSafe":
                        addJca(new Finding("CRYPTOGRAPHIC_ASSET_INVENTORY", fileName, line,
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

            // Skip if parent is already a getInstance()/SecretKeySpec/encoder call — handled by other rules
            if (str.getParentNode().isPresent()) {
                var parent = str.getParentNode().get();
                if (parent instanceof MethodCallExpr &&
                    ((MethodCallExpr)parent).getNameAsString().equals("getInstance")) return;
                if (parent instanceof ObjectCreationExpr) {
                    String t = ((ObjectCreationExpr) parent).getType().getNameAsString();
                    if (t.equals("SecretKeySpec") || t.equals("MessageDigestPasswordEncoder")) return;
                }
            }
            // v2.1: a literal configured inside a Spring @Bean method is framework configuration (L3),
            // e.g. Shiro's HashedCredentialsMatcher.setHashAlgorithmName("md5") in a @Bean.
            final String strLayer = insideBeanMethod(str) ? "L3-SpringSecurityBean" : "L4-RawJCA";
            final String where = strLayer.startsWith("L3") ? " (set inside a Spring @Bean method)" : "";

            if (valU.contains("/ECB/") || valU.equals("ECB")) {
                findings.add(new Finding("INSECURE_CIPHER_MODE_ECB", fileName, line,
                    "Algorithm string \"" + val + "\"" + where + " — ECB mode. Replace with AES/GCM/NoPadding.",
                    strLayer, "CRITICAL", "AES-ECB"));
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
                        "Algorithm string \"" + val + "\"" + where + " — quantum-vulnerable. " +
                        BREAK_REASON.getOrDefault(algo, "Broken by Shor's") + ". " +
                        "Replace: " + PQ_REPLACEMENT.getOrDefault(algo, "See NIST PQC"),
                        strLayer, SEV_QUANTUM_VULNERABLE, algo));
                } else if (status.equals("classicallyBroken")) {
                    findings.add(new Finding("CLASSICALLY_BROKEN_ALGORITHM_STRING", fileName, line,
                        "Algorithm string \"" + val + "\"" + where + " — classically broken. " +
                        BREAK_REASON.getOrDefault(algo, "Known broken") + ". " +
                        "Replace: " + PQ_REPLACEMENT.getOrDefault(algo, "SHA-256 or AES-256-GCM"),
                        strLayer, "HIGH", algo));
                }
                return;
            }
        });
    }

    /**
     * Rule 4d — JWT algorithm enum references (JJWT, Spring Security JOSE, Nimbus JOSE).
     * v2.0 labelled every SignatureAlgorithm.X as JJWT and claimed CBOMkit detects it; CBOMkit's
     * Java support covers JCA and the BouncyCastle light-weight API only, so neither is true.
     * v2.1 attributes the enum to its library from the imports. Spring Security JOSE settings are
     * framework configuration and reported at L3.
     */
    private void checkJwtLibraryEnums(CompilationUnit cu, String fileName) {
        boolean jjwt   = importsPackage(cu, "io.jsonwebtoken");
        boolean spring = importsPackage(cu, "org.springframework.security.oauth2.jose")
            || cu.getPackageDeclaration().map(pd -> pd.getNameAsString().startsWith("org.springframework.security.oauth2")).orElse(false);
        boolean nimbus = importsPackage(cu, "com.nimbusds");
        cu.findAll(FieldAccessExpr.class).forEach(expr -> {
            String scope = expr.getScope().toString();
            String name  = expr.getNameAsString();
            String lib; String layer;
            if ((scope.equals("SignatureAlgorithm") || scope.equals("io.jsonwebtoken.SignatureAlgorithm")) && jjwt
                || scope.equals("Jwts.SIG")) { lib = "JJWT"; layer = "L4-RawJCA"; }
            else if ((scope.equals("SignatureAlgorithm") || scope.equals("MacAlgorithm")) && spring && !jjwt) {
                lib = "Spring Security JOSE"; layer = "L3-SpringSecurityBean"; }
            else if (scope.equals("JWSAlgorithm") && nimbus) { lib = "Nimbus JOSE"; layer = "L4-RawJCA"; }
            else return;
            if (!JWS_NAME.matcher(name).matches()) return;
            // already reported by the NimbusJwtDecoder rule
            if (expr.getParentNode().filter(pn -> pn instanceof MethodCallExpr
                    && List.of("signatureAlgorithm", "macAlgorithm", "jwsAlgorithm").contains(((MethodCallExpr) pn).getNameAsString())).isPresent()
                && cu.toString().contains("NimbusJwtDecoder")) return;

            int    line  = lineOf(expr);
            String algo  = joseToAlgorithm(name);
            String note  = layer.startsWith("L3")
                ? " Not visible to CBOMkit (framework setting, no JCA call)."
                : " Not covered by CBOMkit (its Java rules cover JCA and BouncyCastle only).";
            if (algo.startsWith("HMAC")) {
                findings.add(new Finding("JWT_HMAC_ALGORITHM_DETECTED", fileName, line,
                    lib + " " + scope + "." + name + " — HMAC-SHA JWT. Quantum-safe; verify the key is at least 256 bits." + note,
                    layer, "INFO", algo));
            } else {
                findings.add(new Finding("QUANTUM_VULNERABLE_JWT_ALGORITHM", fileName, line,
                    lib + " " + scope + "." + name + " — " + (algo.equals("RSA") ? "RSA" : "ECDSA") + "-signed JWT. "
                    + BREAK_REASON.getOrDefault(algo, "Shor's algorithm") + ". Replace: ML-DSA (NIST FIPS 204)." + note,
                    layer, SEV_QUANTUM_VULNERABLE, algo));
            }
        });
    }

    // Methods / constructors that take a signing or encryption key
    private static final Set<String> KEY_SINK_METHODS = Set.of(
        "signWith", "setSigningKey", "verifyWith", "decryptWith", "encryptWith", "hmacShaKeyFor",
        "withSecretKey", "HMAC256", "HMAC384", "HMAC512");
    private static final Set<String> KEY_SINK_CTORS = Set.of("SecretKeySpec", "HmacKey", "MACSigner", "MACVerifier", "OctetSequenceKey");

    /**
     * Rule 4e (new in v2.1) — hard-coded cryptographic key: a string literal that reaches a key sink
     * either directly or through a variable/constant initialised with a literal.
     * Severity: CRITICAL when the key material is under 256 bits (32 bytes), HIGH otherwise.
     */
    private void checkHardcodedCryptoKeys(CompilationUnit cu, String fileName) {
        Map<String, VariableDeclarator> literalVars = new HashMap<>();
        for (VariableDeclarator v : cu.findAll(VariableDeclarator.class)) {
            v.getInitializer().filter(Expression::isStringLiteralExpr).ifPresent(init -> {
                String val = init.asStringLiteralExpr().asString();
                if (!val.isBlank() && !val.contains("${")) literalVars.put(v.getNameAsString(), v);
            });
        }
        Set<Node> reported = new HashSet<>();
        List<Expression> sinks = new ArrayList<>();
        for (MethodCallExpr mc : cu.findAll(MethodCallExpr.class))
            if (KEY_SINK_METHODS.contains(mc.getNameAsString())) sinks.add(mc);
        for (ObjectCreationExpr oc : cu.findAll(ObjectCreationExpr.class))
            if (KEY_SINK_CTORS.contains(oc.getType().getNameAsString())) sinks.add(oc);

        for (Expression sink : sinks) {
            List<Expression> args = sink.isMethodCallExpr() ? sink.asMethodCallExpr().getArguments()
                                                            : sink.asObjectCreationExpr().getArguments();
            if (args.isEmpty()) continue;
            // the key is the first argument for SecretKeySpec/hmacShaKeyFor/HMACxxx/withSecretKey,
            // and any argument for signWith/setSigningKey (JJWT accepts (alg, key) and (key, alg))
            String sinkName = sink.isMethodCallExpr() ? sink.asMethodCallExpr().getNameAsString()
                                                      : sink.asObjectCreationExpr().getType().getNameAsString();
            List<Expression> keyArgs = Set.of("signWith", "setSigningKey").contains(sinkName) ? args : List.of(args.get(0));
            for (Expression a : keyArgs) {
                String argText = a.toString();
                boolean b64 = argText.contains("BASE64") || argText.toLowerCase().contains("base64");
                List<StringLiteralExpr> lits = new ArrayList<>(a.findAll(StringLiteralExpr.class));
                for (NameExpr ne : a.findAll(NameExpr.class)) {
                    VariableDeclarator v = literalVars.get(ne.getNameAsString());
                    if (v != null) lits.add(v.getInitializer().get().asStringLiteralExpr());
                }
                for (StringLiteralExpr lit : lits) {
                    if (!reported.add(lit)) continue;
                    String val = lit.asString();
                    if (val.length() < 4 || val.matches("(?i)(HmacSHA\\d+|AES|DES|RSA|UTF-?8|HS\\d+)")) continue;
                    int bytes = b64 ? (val.replace("=", "").length() * 3) / 4 : val.getBytes(StandardCharsets.UTF_8).length;
                    Expression lastArg = args.get(args.size() - 1);
                    String algo = sinkName.equals("SecretKeySpec") && args.size() > 1 && lastArg.isStringLiteralExpr()
                        ? lastArg.asStringLiteralExpr().asString().toUpperCase() : "HMACSHA256";
                    boolean weak = bytes < 32;
                    findings.add(new Finding("HARDCODED_CRYPTO_KEY", fileName, lineOf(lit),
                        "Hard-coded key material (" + bytes + " bytes" + (b64 ? ", Base64-decoded" : "") + ") passed to "
                        + sinkName + "(). Anyone with the source can forge or decrypt. "
                        + (weak ? "Also shorter than 256 bits. " : "")
                        + "Load from a secrets manager or environment instead. Not reported by CBOMkit (it inventories algorithms, not key provenance).",
                        "L4-RawJCA", weak ? "CRITICAL" : "HIGH", algo));
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // LAYER 1 — Configuration Files (CBOMkit misses these)
    // ═══════════════════════════════════════════════════════════

    /** Flattens a Spring .properties or .yml file into (dotted.key, value, line) entries. */
    static List<String[]> flattenConfig(List<String> lines, boolean yaml) {
        List<String[]> out = new ArrayList<>();
        if (!yaml) {
            for (int i = 0; i < lines.size(); i++) {
                String l = lines.get(i).strip();
                if (l.isEmpty() || l.startsWith("#") || l.startsWith("!")) continue;
                // java.util.Properties: key ends at the first unescaped '=', ':' or whitespace
                int k = 0;
                while (k < l.length() && "=: \t".indexOf(l.charAt(k)) < 0) { if (l.charAt(k) == '\\') k++; k++; }
                String key = l.substring(0, Math.min(k, l.length())).strip();
                String rest = k < l.length() ? l.substring(k).strip() : "";
                if (rest.startsWith("=") || rest.startsWith(":")) rest = rest.substring(1).strip();
                out.add(new String[]{key, rest, String.valueOf(i + 1)});
            }
            return out;
        }
        Deque<int[]> indents = new ArrayDeque<>();   // indentation levels
        Deque<String> keys = new ArrayDeque<>();
        for (int i = 0; i < lines.size(); i++) {
            String raw = lines.get(i);
            String t = raw.strip();
            if (t.isEmpty() || t.startsWith("#") || t.equals("---") || t.startsWith("- ") || t.equals("-")) continue;
            int ind = raw.length() - raw.stripLeading().length();
            int c = t.indexOf(':');
            if (c <= 0) continue;
            String key = t.substring(0, c).strip().replaceAll("^[\"']|[\"']$", "");
            String val = t.substring(c + 1).strip();
            while (!indents.isEmpty() && indents.peek()[0] >= ind) { indents.pop(); keys.pop(); }
            List<String> path = new ArrayList<>(keys); java.util.Collections.reverse(path); path.add(key);
            String full = String.join(".", path);
            if (val.isEmpty() || val.equals("|") || val.equals(">")) { indents.push(new int[]{ind}); keys.push(key); }
            else out.add(new String[]{full, val, String.valueOf(i + 1)});
        }
        return out;
    }

    static String cleanValue(String v) {
        String s = v.strip();
        if (s.startsWith("\"") || s.startsWith("'")) {
            char q = s.charAt(0); int e = s.indexOf(q, 1);
            return e > 0 ? s.substring(1, e) : s.substring(1);
        }
        int hash = s.indexOf(" #");
        return (hash >= 0 ? s.substring(0, hash) : s).strip();
    }

    // last key segment naming key material; whole key must also be about crypto/tokens
    private static final Pattern SECRET_LEAF = Pattern.compile(
        "(?i)(^|[-_.])(secret|secret[-_]?key|signing[-_]?key|private[-_]?key|hmac[-_]?key|encryption[-_]?key|jwt[-_]?secret|key)$");
    private static final Pattern CRYPTO_CONTEXT = Pattern.compile("(?i)jwt|jws|jwe|token|sign|hmac|encrypt|crypt|cipher|aes");
    private static final Pattern NOT_KEY_MATERIAL = Pattern.compile(
        "(?i)(client[-_]?secret|key[-_]?store|key[-_]?alias|key[-_]?id|kid|public[-_]?key[-_]?location|uri|url|location|path|file|type|algorithm|expiration|header|prefix|name)");

    /**
     * L1 — Spring configuration files (application*.yml/.yaml/.properties, bootstrap*), every module.
     * v2.0 bugs fixed: comment lines were matched (JKS), ${ENV:default} placeholders were split at
     * the ':' and measured as 1-character secrets, and OAuth client secrets were treated as HMAC keys.
     */
    private void scanConfigFile(Path file) {
        String name = rel(file);
        boolean yaml = name.endsWith(".yml") || name.endsWith(".yaml");
        List<String> lines;
        try { lines = Files.readAllLines(file, StandardCharsets.UTF_8); }
        catch (Exception e) {
            try { lines = Files.readAllLines(file, StandardCharsets.ISO_8859_1); }
            catch (Exception e2) { System.err.println("Could not read config: " + name); return; }
        }
        for (String[] kv : flattenConfig(lines, yaml)) {
            String key = kv[0], keyL = key.toLowerCase();
            String val = cleanValue(kv[1]);
            int line = Integer.parseInt(kv[2]);
            if (val.isEmpty()) continue;

            if (keyL.endsWith("key-store-type") || keyL.endsWith("keystoretype") || keyL.endsWith("trust-store-type")) {
                if (val.equalsIgnoreCase("JKS")) findings.add(new Finding("DEPRECATED_KEYSTORE_TYPE", name, line,
                    key + "=JKS — proprietary keystore format; Java 9+ default is PKCS12. Migrate to PKCS12. "
                    + "Not visible to CBOMkit (configuration file).", "L1-ConfigFile", "MEDIUM", "JKS"));
                continue;
            }
            if (keyL.matches(".*ssl\\.(protocol|enabled-protocols)$")) {
                String vU = val.toUpperCase();
                if (vU.matches(".*\\b(SSLV3|TLSV1|TLSV1\\.1)\\b.*") && !vU.matches(".*TLSV1\\.[23].*") || vU.contains("SSL")) {
                    findings.add(new Finding("DEPRECATED_TLS_VERSION", name, line,
                        key + "=" + val + " — TLS 1.0/1.1 and SSL are deprecated (RFC 8996). Use TLSv1.2 or TLSv1.3. "
                        + "Not visible to CBOMkit (configuration file).", "L1-ConfigFile", "HIGH", "TLS"));
                } else {
                    findings.add(new Finding("TLS_PROTOCOL_CONFIGURED", name, line,
                        key + "=" + val + " — TLS configured. Recorded for CBOM inventory. "
                        + "Not visible to CBOMkit (configuration file).", "L1-ConfigFile", "INFO", "TLS"));
                }
                continue;
            }
            String leaf = key.contains(".") ? key.substring(key.lastIndexOf('.') + 1) : key;
            if (!SECRET_LEAF.matcher(leaf).find()) continue;
            if (NOT_KEY_MATERIAL.matcher(leaf).find() || keyL.contains("client-secret") || keyL.contains("clientsecret")) continue;
            if (!CRYPTO_CONTEXT.matcher(key).find()) continue;
            if (val.contains("${") || val.startsWith("ENC(") || val.startsWith("{cipher}")) continue; // externalised / encrypted
            if (val.matches("(?i)^(classpath\\*?|file|https?|vault):.*|^/.*|.*\\.(key|pem|pub|der|jks|p12|pfx|crt|cer)$")) continue; // a location, not key material

            int bytes = val.getBytes(StandardCharsets.UTF_8).length;
            boolean hex = val.matches("[0-9a-fA-F]{32,}");
            boolean b64 = !hex && val.matches("[A-Za-z0-9+/]{24,}={0,2}");
            int keyBytes = hex ? bytes / 2 : b64 ? (val.replace("=", "").length() * 3) / 4 : bytes;
            boolean weak = keyBytes < 32;
            String algo = keyL.matches(".*(jwt|jws|token|hmac|sign).*") ? "HMACSHA256" : "SECRET-KEY";
            findings.add(new Finding(weak ? "WEAK_SECRET_IN_CONFIG" : "HARDCODED_SECRET_IN_CONFIG", name, line,
                key + " is a hard-coded key in configuration (" + keyBytes + " bytes"
                + (hex ? ", hex" : b64 ? ", Base64" : "") + ")." + (weak ? " Shorter than 256 bits." : "")
                + " Move it to a secrets manager or an environment variable. Not visible to CBOMkit (configuration file).",
                "L1-ConfigFile", weak ? "CRITICAL" : "HIGH", algo));
        }
    }

    /** L1 — build files in every module (Maven pom.xml and Gradle scripts). */
    private void scanBuildFile(Path file) {
        String name = rel(file);
        String content;
        try { content = Files.readString(file, StandardCharsets.UTF_8); }
        catch (Exception e) { return; }
        String L1 = "L1-MavenDependency";
        if (content.contains("bcprov-jdk15on") || content.contains("bcpkix-jdk15on")) {
            findings.add(new Finding("LEGACY_BOUNCY_CASTLE", name, 0,
                "Legacy BouncyCastle '*-jdk15on' artifact (no longer updated). Migrate to '*-jdk18on'. "
                + "Not visible to CBOMkit (build file).", L1, "MEDIUM", "BouncyCastle"));
        }
        if (content.contains("nimbus-jose-jwt")) {
            findings.add(new Finding("NIMBUS_JOSE_JWT_PRESENT", name, 0,
                "nimbus-jose-jwt declared directly. Verify version >= 10.0.1 (CVE-2025-53864). Recorded for inventory.",
                L1, "INFO", "JOSE"));
        }
        Matcher m = Pattern.compile("spring-security-oauth2</artifactId>\\s*<version>\\s*2\\.").matcher(content);
        if (m.find() || content.matches("(?s).*spring-security-oauth2:2\\..*")) {
            findings.add(new Finding("LEGACY_SPRING_SECURITY_OAUTH2", name, 0,
                "spring-security-oauth2 2.x (end of life 2022). Migrate to Spring Authorization Server / Spring Security 6.",
                L1, "HIGH", "OAuth2"));
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
        long miss   = findings.stream().filter(f -> !f.cbomkitExpected).count();

        System.out.println("══════════════════════════════════════════════");
        System.out.printf(" CRITICAL: %d  HIGH: %d  MEDIUM: %d  INFO: %d%n", crit, high, medium, info);
        System.out.printf(" Quantum-vulnerable (Shor's): %d%n", qVuln);
        System.out.printf(" Classically broken: %d%n", cBrk);
        System.out.printf(" Outside CBOMkit's JCA rules: %d of %d (%.0f%%)%n",
            miss, findings.size(), findings.isEmpty() ? 0.0 : miss * 100.0 / findings.size());
        System.out.printf(" By context: main=%d sample=%d docs=%d%n",
            findings.stream().filter(f -> "main".equals(f.context)).count(),
            findings.stream().filter(f -> "sample".equals(f.context)).count(),
            findings.stream().filter(f -> "docs".equals(f.context)).count());
        System.out.printf(" Java files scanned: %d, parse failures: %d%n", javaFilesScanned, parseFailures.size());
        System.out.println("══════════════════════════════════════════════");
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
        sb.append("      \"version\": \"2.1\",\n");
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
        sb.append("      {\"name\": \"scannedBy\",    \"value\": \"SpringCryptoScanner v2.1 — IIT Jodhpur\"},\n");
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
            sb.append("        {\"name\": \"layer\",    \"value\": \"").append(escapeJson(f.layer)).append("\"},\n");
            sb.append("        {\"name\": \"detection-rule\",  \"value\": \"").append(escapeJson(f.rule)).append("\"},\n");
            sb.append("        {\"name\": \"severity\",        \"value\": \"").append(escapeJson(f.severity)).append("\"},\n");
            sb.append("        {\"name\": \"quantum-status\",  \"value\": \"").append(escapeJson(f.quantumStatus)).append("\"},\n");
            sb.append("        {\"name\": \"source-file\",     \"value\": \"").append(escapeJson(f.file)).append("\"},\n");
            sb.append("        {\"name\": \"source-line\",     \"value\": \"").append(f.line).append("\"},\n");
            sb.append("        {\"name\": \"pq-replacement\",  \"value\": \"").append(escapeJson(f.replacement)).append("\"},\n");
            sb.append("        {\"name\": \"code-context\",    \"value\": \"").append(f.context).append("\"},\n");
            // true = produced by a JCA call that CBOMkit's rules cover; actual CBOMkit output is compared separately
            sb.append("        {\"name\": \"cbomkit-expected\", \"value\": \"").append(f.cbomkitExpected).append("\"}\n");
            sb.append("      ]\n");
            sb.append("    }");
            if (i < findings.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");
        sb.append("  \"vulnerabilities\": [],\n");

        long miss = findings.stream().filter(f -> !f.cbomkitExpected).count();
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
        sb.append("      \"outsideCbomkitJcaRules\": ").append(miss).append(",\n");
        sb.append("      \"javaFilesScanned\": ").append(javaFilesScanned).append(",\n");
        sb.append("      \"javaParseFailures\": ").append(parseFailures.size()).append(",\n");
        sb.append("      \"note\": \"cbomkit-expected=true marks findings from JCA calls covered by CBOMkit rules; whether CBOMkit reports them must be checked against its actual output.\"\n");
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
