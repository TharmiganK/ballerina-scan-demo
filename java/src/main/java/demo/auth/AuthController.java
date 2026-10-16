package demo.auth;

import io.jsonwebtoken.Jwts;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final SecretKeySpec PII_KEY = new SecretKeySpec(loadPiiKey(Path.of("keys/pii.key")), "AES");

    // Vulnerable: ballerina/crypto:2 (CWE-916) - a BCrypt work factor of 4 is fast enough to brute force.
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(4);
    private final Map<String, UserRecord> users = new ConcurrentHashMap<>();

    public record Credentials(String username, String password) {
    }

    public record Registration(String username, String password, String nationalId) {
    }

    public record TokenResponse(String accessToken, int expiresIn) {
    }

    record UserRecord(String username, String passwordHash, byte[] encryptedNationalId) {
    }

    @PostMapping("/users")
    public ResponseEntity<Void> register(@RequestBody Registration registration) throws GeneralSecurityException {
        String passwordHash = passwordEncoder.encode(registration.password());
        byte[] encryptedNationalId = encryptNationalId(registration.nationalId());
        users.put(registration.username(),
                new UserRecord(registration.username(), passwordHash, encryptedNationalId));
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/tokens")
    public ResponseEntity<TokenResponse> issue(@RequestBody Credentials credentials) {
        UserRecord user = users.get(credentials.username());
        if (user == null || !passwordEncoder.matches(credentials.password(), user.passwordHash())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(new TokenResponse(issueToken(credentials.username()), 3600));
    }

    // Vulnerable: ballerina/jwt:1 (CWE-347) - the token is not signed, so anyone can forge one.
    static String issueToken(String username) {
        return Jwts.builder()
                .issuer("auth-service")
                .subject(username)
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .compact();
    }

    // Vulnerable: ballerina/crypto:1 (CWE-327) - ECB mode leaks which users share a national ID prefix.
    static byte[] encryptNationalId(String nationalId) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, PII_KEY);
        return cipher.doFinal(nationalId.getBytes(StandardCharsets.UTF_8));
    }

    // Vulnerable: ballerina/crypto:3 (CWE-329) - every export reuses the same hard-coded IV.
    public static byte[] encryptExport(byte[] payload) throws GeneralSecurityException {
        byte[] iv = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, PII_KEY, new GCMParameterSpec(128, iv));
        return cipher.doFinal(payload);
    }

    // Vulnerable: ballerina:1 (CWE-248) - a missing key file crashes class loading instead of failing startup cleanly.
    private static byte[] loadPiiKey(Path path) {
        try {
            return Arrays.copyOf(Files.readAllBytes(path), 16);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
