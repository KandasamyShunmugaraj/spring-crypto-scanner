package demo;
import org.springframework.context.annotation.Bean;
// Bug 9: algorithm configured in a @Bean is framework configuration. Expected: L3, MD5, HIGH.
public class Shiro {
    @Bean Object matcher() { var m = new org.apache.shiro.authc.credential.HashedCredentialsMatcher(); m.setHashAlgorithmName("md5"); return m; }
    @Bean Object enc() { return org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance(); } // Expected: PLAINTEXT_PASSWORD_STORAGE, CRITICAL
}
