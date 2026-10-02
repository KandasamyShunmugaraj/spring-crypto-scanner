package demo;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
// Bug 5 (missed by v2.0): hard-coded 12-byte signing key. Expected: HARDCODED_CRYPTO_KEY, CRITICAL.
// Also expected: JWT_HMAC_ALGORITHM_DETECTED attributed to JJWT.
public class TokenUtil {
    private static final String SECRET = "changeme1234";
    String t() { return Jwts.builder().signWith(SignatureAlgorithm.HS256, SECRET).compact(); }
}
