package demo;
// Bug 1: v2.0 could not parse records/text blocks and silently skipped the file.
// Expected v2.1: CLASSICALLY_BROKEN_JCA_ALGORITHM MD5.
public record Modern(String v) {
    static final String Q = """
        text block
        """;
    byte[] h() throws Exception { return java.security.MessageDigest.getInstance("MD5").digest(v.getBytes()); }
}
