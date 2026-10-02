package demo;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
// Bug 3: v2.0 reported both decoders as CRITICAL "MISSING_JWT_ALGORITHM_WHITELIST" (false positive).
// Expected v2.1: JWT_DECODER_SIGNATURE_ALGORITHM, RSA (RS256 default) and RSA (RS512 explicit).
public class JwtConfig {
    @Bean Object a(java.security.interfaces.RSAPublicKey k) { return NimbusJwtDecoder.withPublicKey(k).build(); }
    @Bean Object b(java.security.interfaces.RSAPublicKey k) { return NimbusJwtDecoder.withPublicKey(k).signatureAlgorithm(SignatureAlgorithm.RS512).build(); }
    // Expected: HMACSHA256, INFO
    @Bean Object c(javax.crypto.SecretKey k) { return NimbusJwtDecoder.withSecretKey(k).build(); }
}
