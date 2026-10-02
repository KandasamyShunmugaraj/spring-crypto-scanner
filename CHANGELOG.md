# SpringCryptoScanner — CHANGELOG

## v2.1 (2 October 2026) — correctness fixes

The v2.0 results in the thesis (35 findings, 22 CRITICAL, CBOMkit 0) were re-checked finding by
finding on the same 10 projects at the same commits. The table below lists every v2.0 defect found
and the evidence for it. `fixtures/v21-regression/` contains one test case per defect.

| # | Defect in v2.0 | Effect on thesis results | Evidence | Fix in v2.1 |
|---|---|---|---|---|
| 1 | `StaticJavaParser` used its default language level, so records, text blocks, etc. failed to parse and the file was skipped with only a stderr line | 60 Java files never scanned (24 in spring-authorization-server, 19 in spring-cloud-alibaba, 7 in spring-security-samples, 6 in jhipster, 3 in spring-cloud-vault, 1 in ali-bouali) | `Could not parse:` lines in v2.0 logs | Parser at `BLEEDING_EDGE`; failures counted and reported in the CBOM (`javaParseFailures`) |
| 2 | Test exclusion missed Gradle test sets (`src/integTest`) and `*ITest.java` | 1 finding from an integration test (spring-security-samples `WebfluxX509ApplicationITest`) | file path | One test-path pattern used everywhere; every finding tagged `code-context` = main / sample / docs |
| 3 | L3 `MISSING_JWT_ALGORITHM_WHITELIST` flagged every `NimbusJwtDecoder.withPublicKey()/withSecretKey()` as CRITICAL algorithm-confusion | 4 CRITICAL false positives (spring-security-samples ×2, jhipster ×1, spring-authorization-server ×1). jhipster's was also labelled RSA although it is an HMAC key | Spring Security `NimbusJwtDecoder`: both builders create a `SingleKeyJWSKeySelector` for exactly one algorithm (default RS256 / HS256); no `setJwsAlgorithms()` method exists on them | Replaced by inventory rule `JWT_DECODER_SIGNATURE_ALGORITHM`, which records the configured algorithm (or "runtime" if not statically resolvable) |
| 4 | L1 secret check split each line at the first `:` | 3 CRITICAL false positives in spring-boot-todo: `client-secret= ${GITHUB_CLIENTSECRET:}` was measured as the 1-character secret `}`. Also: commented-out `key-store-type: JKS` was reported (crypto-gap-test); only the root `src/main/resources` was read | spring-boot-todo `application.properties` lines 11, 15, 19 | Real `.properties` / nested-YAML parsing; comments ignored; `${…}` placeholders, `ENC(…)`, file locations and OAuth client secrets skipped; only key-material settings in a crypto/JWT context checked; every module scanned |
| 5 | No rule for hard-coded keys in Java | Real issue missed: spring-boot-todo `JwtUtil.java:18` signs JWTs with a 20-byte literal key | source line | New L4 rule `HARDCODED_CRYPTO_KEY` (literal or constant reaching `signWith`, `hmacShaKeyFor`, `SecretKeySpec`, …) |
| 6 | Every `SignatureAlgorithm.X` labelled "JJWT … CBOMkit detects this via JJWT-specific rules" | 5 spring-authorization-server findings mislabelled; claim about CBOMkit wrong (its Java support is JCA + BouncyCastle light-weight API only, per CBOMkit README) | imports of the files; CBOMkit README "Supported languages and libraries" | Library attributed from imports (JJWT / Spring Security JOSE / Nimbus). Spring Security JOSE settings reported at L3 |
| 7 | L2 flagged every `@Convert`, including enum/date converters | none in the corpus, but any non-crypto converter was reported | fixture `Customer.status` | Converter class resolved; reported only if it uses crypto; cipher algorithm taken from the converter |
| 8 | `JCA getInstance` matched only simple class names | `java.security.MessageDigest.getInstance("MD5")` not detected | fixture `Modern.java` | Fully qualified names accepted |
| 9 | `Cipher.getInstance("AES")` treated as safe AES | It is AES/ECB (provider default) | JCA documentation | Reported as `INSECURE_CIPHER_MODE_ECB` |
| 10 | `SecretKeySpec(key, off, len, "AES")` (4-argument form) ignored | missed inventory in crypto-gap-test | source | Algorithm read from the last argument |
| 11 | `cbomkit-detects` hard-coded to `false` in the web API; in the CBOM it was simply "layer == L4" | Gap figures were assumptions, not measurements | `ScannerWebController` | Renamed to `cbomkit-expected`: true only for JCA calls CBOMkit's rules cover. Actual CBOMkit output must be compared separately |

### New framework-layer coverage (things CBOMkit cannot see by design)

* L3 Spring Security password encoders: `NoOpPasswordEncoder` (CRITICAL), `MessageDigestPasswordEncoder`,
  `StandardPasswordEncoder`, `LdapShaPasswordEncoder`, `Md4PasswordEncoder` (HIGH), bcrypt/PBKDF2/scrypt/Argon2 (INFO inventory).
* L3 `Encryptors.*` (queryableText HIGH, standard/text MEDIUM, stronger/delux INFO, noOpText CRITICAL).
* L3 algorithm strings configured inside a Spring `@Bean` method (e.g. Shiro `setHashAlgorithmName("md5")`).
* L1 deprecated TLS versions (`TLSv1`, `TLSv1.1`, `SSL*`) and hard-coded key material ≥ 256 bits (HIGH).

### Unchanged on purpose

* Severity policy. Quantum-vulnerable public-key algorithms (RSA/EC/DSA/DH) are still CRITICAL, as in v2.0.
  This is one constant, `SEV_QUANTUM_VULNERABLE`; changing it re-grades all such findings consistently.
* CBOM property names (`layer`, `detection-rule`, …) except `cbomkit-detects` → `cbomkit-expected`, plus new `code-context`.

### Results on the thesis corpus (same commits as v2.0)

| Project | v2.0 total / CRIT | v2.1 total / actionable* / CRIT | L1 | L2 | L3 | L4 | CBOMkit-rule-covered | CBOMkit file coverage** |
|---|---|---|---|---|---|---|---|---|
| spring-security-samples | 6 / 2 | 8 / 4 / 4 | 0 | 0 | 4 | 4 | 3 | 100% |
| spring-boot-todo | 4 / 3 | 3 / 2 / 2 | 0 | 0 | 1 | 2 | 0 | 100% |
| spring-boot-examples | 2 / 0 | 2 / 2 / 0 | 0 | 0 | 2 | 0 | 0 | 100% |
| jhipster-sample-app | 1 / 1 | 5 / 1 / 0 | 2 | 0 | 3 | 0 | 0 | 100% |
| ali-bouali-jwt-security | 1 / 1 | 3 / 1 / 0 | 1 | 0 | 1 | 1 | 0 | 100% |
| piomin-microservices | 0 / 0 | 0 / 0 / 0 | 0 | 0 | 0 | 0 | 0 | 100% |
| spring-petclinic | 0 / 0 | 0 / 0 / 0 | 0 | 0 | 0 | 0 | 0 | 100% |
| spring-cloud-alibaba | 2 / 0 | 2 / 2 / 0 | 0 | 0 | 0 | 2 | 2 | 100% |
| spring-authorization-server | 19 / 15 | 29 / 14 / 14 | 1 | 0 | 13 | 15 | 14 | **9.1%** |
| spring-cloud-vault | 0 / 0 | 2 / 2 / 0 | 2 | 0 | 0 | 0 | 0 | 100% |
| **Total** | **35 / 22** | **54 / 28 / 20** | **6** | **0** | **24** | **24** | **19** | |

\* actionable = CRITICAL + HIGH + MEDIUM (INFO entries are CBOM inventory, not issues).
\** share of non-test Java files CBOMkit 2.3.0 indexes, from `scripts/cbomkit_coverage.py` (a re-implementation of
cbomkit-lib 1.1.0 `JavaIndexService`; confirmed against CBOMkit's own scan log for spring-authorization-server,
which indexed only `buildSrc` and one small folder). Spring projects name their Gradle files `<module>.gradle`,
which CBOMkit does not recognise as modules.

Per-project CBOMs: `results/v2.1/`. v2.0 baseline CBOMs for the same commits: `results/v2.0/`.
