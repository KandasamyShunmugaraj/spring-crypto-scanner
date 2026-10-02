# v2.1 regression fixture

One small Spring project with one case per bug fixed in v2.1 (see comments in each file).
Run the scanner on this folder and compare with `EXPECTED.txt`:

```bash
java -cp target/classes:<javaparser jars> com.thesis.cryptoscanner.SpringCryptoScanner fixtures/v21-regression \
  | grep -E '^\s+\[' | sed -E 's/ — .*//; s/^\s+//' | sort | diff - fixtures/v21-regression/EXPECTED.txt
```

No output from `diff` means every rule behaves as expected. v2.0 produced 13 findings here, 7 of them wrong
(3 JWT whitelist false positives, 2 placeholder "secrets", 1 commented-out JKS, 1 non-crypto @Convert)
and missed 3 (MD5 in a record, AES default-ECB via fully-qualified Cipher, hard-coded JWT key).
