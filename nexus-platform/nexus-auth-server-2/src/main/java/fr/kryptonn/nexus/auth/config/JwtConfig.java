package fr.kryptonn.nexus.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Configuration
@Slf4j
public class JwtConfig {

    private static final String STATIC_KEY_ID = "nexus-auth-key-1"; // ID de clé statique pour les tests

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        log.info("=== CONFIGURATION JWK SOURCE ===");

        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        log.info("Clé RSA générée - Algorithme: {}, Format: {}",
                publicKey.getAlgorithm(), publicKey.getFormat());
        log.info("Taille de la clé: {} bits", publicKey.getModulus().bitLength());

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(STATIC_KEY_ID) // Utiliser un ID statique pour les tests
                .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256) // Forcer RS256
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE) // Spécifier l'usage
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);

        log.info("JWK Set créé avec {} clé(s)", jwkSet.getKeys().size());
        log.info("ID de la clé: {}", rsaKey.getKeyID());
        log.info("Algorithme: {}", rsaKey.getAlgorithm());

        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        log.info("Configuration du JwtDecoder avec JWKSource");
        JwtDecoder decoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        log.info("JwtDecoder configuré avec succès");
        return decoder;
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        log.info("Configuration du JwtEncoder avec JWKSource");
        JwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
        log.info("JwtEncoder configuré avec succès");
        return encoder;
    }

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(
            JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {

        log.info("Configuration du TokenGenerator");

        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);

        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        DelegatingOAuth2TokenGenerator tokenGenerator = new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);

        log.info("TokenGenerator configuré avec succès");
        return tokenGenerator;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            log.debug("=== PERSONNALISATION JWT ===");

            JwtClaimsSet.Builder claims = context.getClaims();

            // Claims personnalisés
            claims.claim("scope", context.getAuthorizedScopes());
            claims.claim("client_id", context.getRegisteredClient().getClientId());

            // Claims utilisateur si disponibles
            Authentication authentication = context.getPrincipal();
            if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
                UserDetails userDetails = (UserDetails) authentication.getPrincipal();

                log.debug("Ajout des claims utilisateur pour: {}", userDetails.getUsername());

                claims.claim("username", userDetails.getUsername());
                claims.claim("email", userDetails.getUsername()); // Email comme username

                // Extraction des autorités
                var authorities = userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList();

                claims.claim("authorities", authorities);

                log.debug("Autorités ajoutées: {}", authorities);
            }

            // Expiration token : 1 heure pour access token
            if (context.getTokenType().getValue().equals("access_token")) {
                Instant expiration = Instant.now().plus(Duration.ofHours(1));
                claims.expiresAt(expiration);
                log.debug("Access token expire à: {}", expiration);
            }
            // Expiration refresh token : 7 jours
            else if (context.getTokenType().getValue().equals("refresh_token")) {
                Instant expiration = Instant.now().plus(Duration.ofDays(7));
                claims.expiresAt(expiration);
                log.debug("Refresh token expire à: {}", expiration);
            }

            // Ajouter l'issuer explicitement
            claims.issuer(context.getAuthorizationServerContext().getIssuer());

            // Ajouter un JTI unique
            claims.id(UUID.randomUUID().toString());

            log.debug("Claims finaux: {}", claims.build().getClaims().keySet());
        };
    }

    private static KeyPair generateRsaKey() {
        log.info("Génération d'une nouvelle paire de clés RSA...");

        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // 2048 bits pour RSA
            keyPair = keyPairGenerator.generateKeyPair();

            log.info("✅ Paire de clés RSA générée avec succès");
            log.info("Clé publique - Algorithme: {}", keyPair.getPublic().getAlgorithm());
            log.info("Clé privée - Algorithme: {}", keyPair.getPrivate().getAlgorithm());

        } catch (Exception ex) {
            log.error("❌ Erreur lors de la génération de la clé RSA: {}", ex.getMessage());
            throw new IllegalStateException("Erreur lors de la génération de la clé RSA", ex);
        }
        return keyPair;
    }
}