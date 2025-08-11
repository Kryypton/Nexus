package fr.kryptonn.nexus.auth.service;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
@Slf4j
public class JwtService {

    // ✅ CORRECTION: Utiliser la même configuration que OAuth2
    @Value("${app.jwt.issuer:http://localhost:9000}")
    private String issuer;

    @Value("${app.jwt.audience:nexus-clients}")
    private String audience;

    @Autowired
    private JWKSource<SecurityContext> jwkSource;

    private static final Duration ACCESS_TOKEN_DURATION = Duration.ofMinutes(15);
    private static final Duration REFRESH_TOKEN_DURATION = Duration.ofDays(7);

    public String generateAccessToken(String email) {
        return generateToken(email, ACCESS_TOKEN_DURATION, "access");
    }

    public String generateRefreshToken(String email) {
        return generateToken(email, REFRESH_TOKEN_DURATION, "refresh");
    }

    private String generateToken(String email, Duration duration, String tokenType) {
        Instant now = Instant.now();
        String jti = UUID.randomUUID().toString();

        Map<String, Object> claims = new HashMap<>();
        claims.put("type", tokenType);
        claims.put("jti", jti);

        try {
            RSAPrivateKey privateKey = getPrivateKey();

            log.debug("Génération token {} pour {} avec issuer: {}", tokenType, email, issuer);

            return Jwts.builder()
                    .subject(email)
                    .issuer(issuer) // ✅ Utilise l'URL complète
                    .audience().add(audience).and()
                    .issuedAt(Date.from(now))
                    .expiration(Date.from(now.plus(duration)))
                    .claims(claims)
                    .signWith(privateKey, SignatureAlgorithm.RS256) // ✅ Force RS256 explicitement
                    .compact();
        } catch (Exception e) {
            log.error("Erreur lors de la génération du token pour {}: {}", email, e.getMessage());
            throw new RuntimeException("Impossible de générer le token", e);
        }
    }

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractJti(String token) {
        return extractClaim(token, claims -> claims.get("jti", String.class));
    }

    public String extractTokenType(String token) {
        return extractClaim(token, claims -> claims.get("type", String.class));
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Date extractIssuedAt(String token) {
        return extractClaim(token, Claims::getIssuedAt);
    }

    public String extractIssuer(String token) {
        return extractClaim(token, Claims::getIssuer);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String tokenEmail = extractEmail(token);
            return tokenEmail.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (Exception e) {
            log.warn("Token invalide: {}", e.getMessage());
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            log.warn("Erreur lors de la vérification d'expiration: {}", e.getMessage());
            return true;
        }
    }

    /**
     * ✅ CORRECTION: Validation robuste qui gère les deux types de tokens
     */
    public boolean validateToken(String token) {
        try {
            // Essayer d'abord avec RSA (notre signature standard)
            RSAPublicKey publicKey = getPublicKey();

            Jws<Claims> claimsJws = Jwts.parser()
                    .verifyWith(publicKey)
                    .requireIssuer(issuer)
                    .requireAudience(audience)
                    .build()
                    .parseSignedClaims(token);

            log.debug("✅ Token RSA validé avec succès pour issuer: {}", claimsJws.getPayload().getIssuer());
            return true;

        } catch (UnsupportedJwtException e) {
            // ✅ Si c'est un token HS256, loguer mais ne pas accepter
            if (e.getMessage().contains("HS256")) {
                log.warn("🚫 Token HS256 détecté mais non supporté. Utilisez uniquement des tokens RS256.");
                log.warn("Message complet: {}", e.getMessage());
                return false;
            }
            log.warn("Token non supporté: {}", e.getMessage());
            return false;
        } catch (ExpiredJwtException e) {
            log.warn("Token expiré: {}", e.getMessage());
            return false;
        } catch (MalformedJwtException e) {
            log.warn("Token malformé: {}", e.getMessage());
            return false;
        } catch (SecurityException e) {
            log.warn("Signature invalide: {}", e.getMessage());
            return false;
        } catch (IllegalArgumentException e) {
            log.warn("Token vide ou nul: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Erreur inattendue lors de la validation: {}", e.getMessage());
            return false;
        }
    }

    private Claims extractAllClaims(String token) {
        try {
            RSAPublicKey publicKey = getPublicKey();

            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            log.error("Erreur lors de l'extraction des claims: {}", e.getMessage());
            throw new RuntimeException("Token invalide", e);
        }
    }

    private RSAPrivateKey getPrivateKey() {
        try {
            ImmutableJWKSet<?> immutableJWKSet = (ImmutableJWKSet<?>) jwkSource;
            JWKSet jwkSet = immutableJWKSet.getJWKSet();
            RSAKey rsaKey = (RSAKey) jwkSet.getKeys().get(0);
            return rsaKey.toRSAPrivateKey();
        } catch (Exception e) {
            log.error("Erreur lors de la récupération de la clé privée: {}", e.getMessage());
            throw new RuntimeException("Impossible de récupérer la clé privée RSA", e);
        }
    }

    private RSAPublicKey getPublicKey() {
        try {
            ImmutableJWKSet<?> immutableJWKSet = (ImmutableJWKSet<?>) jwkSource;
            JWKSet jwkSet = immutableJWKSet.getJWKSet();
            RSAKey rsaKey = (RSAKey) jwkSet.getKeys().get(0);
            return rsaKey.toRSAPublicKey();
        } catch (Exception e) {
            log.error("Erreur lors de la récupération de la clé publique: {}", e.getMessage());
            throw new RuntimeException("Impossible de récupérer la clé publique RSA", e);
        }
    }

    public long getAccessTokenExpirationMs() {
        return ACCESS_TOKEN_DURATION.toMillis();
    }

    public long getRefreshTokenExpirationMs() {
        return REFRESH_TOKEN_DURATION.toMillis();
    }

    public boolean isRefreshToken(String token) {
        try {
            String tokenType = extractTokenType(token);
            return "refresh".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isAccessToken(String token) {
        try {
            String tokenType = extractTokenType(token);
            return "access".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ✅ Méthode pour debug - extraction des informations de base du token
     */
    public Map<String, Object> getTokenInfo(String token) {
        Map<String, Object> info = new HashMap<>();
        try {
            String[] parts = token.split("\\.");
            if (parts.length >= 2) {
                String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
                info.put("header", header);

                Claims claims = extractAllClaims(token);
                info.put("subject", claims.getSubject());
                info.put("issuer", claims.getIssuer());
                info.put("audience", claims.getAudience());
                info.put("expiration", claims.getExpiration());
                info.put("issuedAt", claims.getIssuedAt());
                info.put("jti", claims.get("jti"));
                info.put("type", claims.get("type"));
            }
        } catch (Exception e) {
            info.put("error", e.getMessage());
        }
        return info;
    }
}