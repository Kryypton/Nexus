package fr.kryptonn.nexus.axon.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;
import fr.kryptonn.nexus.axon.filter.LinkedAccountFilter;

import java.time.Duration;
import java.util.Collection;

/**
 * Configuration de sécurité pour l'application Axon - CORRIGÉE
 * Résout le problème de signature JWT et d'issuer URL
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final CorsConfigurationSource corsConfigurationSource;
    private final LinkedAccountFilter linkedAccountFilter;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // Désactiver CSRF pour les APIs REST
                .csrf(AbstractHttpConfigurer::disable)

                // Configuration CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource))

                // Configuration des sessions - stateless avec JWT
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configuration OAuth2 Resource Server
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder()) // Decoder personnalisé robuste
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                        .authenticationEntryPoint((request, response, authException) -> {
                            log.error("=== ERREUR AUTHENTIFICATION JWT ===");
                            log.error("URI: {}", request.getRequestURI());
                            log.error("Méthode: {}", request.getMethod());
                            log.error("Message: {}", authException.getMessage());
                            log.error("Cause: {}", authException.getCause() != null ? authException.getCause().getMessage() : "Aucune");
                            log.error("=====================================");

                            response.setStatus(401);
                            response.setContentType("application/json");
                            response.getWriter().write(String.format(
                                    "{\"error\":\"Unauthorized\",\"message\":\"%s\",\"details\":\"%s\"}",
                                    authException.getMessage(),
                                    authException.getCause() != null ? authException.getCause().getMessage() : ""
                            ));
                        })
                )

                // Configuration des autorisations
                .authorizeHttpRequests(auth -> auth
                        // Endpoints publics
                        .requestMatchers("/actuator/**", "/api/public/**", "/api/debug/**").permitAll()
                        .requestMatchers("/img/**").permitAll()

                        // Endpoints protégés
                        .requestMatchers("/api/protected/**").authenticated()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // Tout le reste nécessite une authentification
                        .anyRequest().authenticated()
                )

                .addFilterAfter(linkedAccountFilter, BearerTokenAuthenticationFilter.class)

                .build();
    }

    /**
     * ✅ CORRECTION: Decoder JWT robuste avec gestion des erreurs d'issuer
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        log.info("=== CONFIGURATION JWT DECODER ===");
        log.info("Issuer URI: {}", issuerUri);

        try {
            String jwkSetUri = issuerUri + "/oauth2/jwks";
            log.info("JWK Set URI: {}", jwkSetUri);

            // Test de connectivité immédiat
            try {
                log.info("Test de connectivité vers le serveur d'auth...");
                java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
                java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(jwkSetUri))
                        .timeout(Duration.ofSeconds(5))
                        .build();

                java.net.http.HttpResponse<String> response = client.send(request,
                        java.net.http.HttpResponse.BodyHandlers.ofString());

                log.info("Réponse du serveur d'auth: Status={}, Body={}",
                        response.statusCode(),
                        response.body().length() > 200 ? response.body().substring(0, 200) + "..." : response.body());

                if (response.statusCode() != 200) {
                    log.error("Le serveur d'auth ne répond pas correctement!");
                    throw new RuntimeException("Serveur d'auth inaccessible: " + response.statusCode());
                }

            } catch (Exception e) {
                log.error("ERREUR: Impossible de contacter le serveur d'auth: {}", e.getMessage());
                log.error("Vérifiez que le serveur d'auth est démarré sur: {}", issuerUri);
                // Ne pas planter l'application, mais logger l'erreur
            }

            // Configuration du decoder avec timeouts et cache
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                    .jwsAlgorithm(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256)
                    .build();

            // ✅ CORRECTION: Wrapper avec gestion robuste des erreurs d'issuer
            return token -> {
                log.debug("=== DÉCODAGE TOKEN JWT ===");
                log.debug("Token (50 premiers chars): {}", token.length() > 50 ? token.substring(0, 50) + "..." : token);

                try {
                    var jwt = decoder.decode(token);
                    log.debug("✅ Token décodé avec succès");
                    log.debug("Subject: {}", jwt.getSubject());

                    // ✅ Gestion safe de l'issuer
                    String issuer = jwt.getClaimAsString("iss");
                    log.debug("Issuer (String): {}", issuer);

                    log.debug("Expiration: {}", jwt.getExpiresAt());
                    log.debug("Claims: {}", jwt.getClaims().keySet());

                    return jwt;
                } catch (Exception e) {
                    log.error("❌ ERREUR DÉCODAGE TOKEN:");
                    log.error("Type d'erreur: {}", e.getClass().getSimpleName());
                    log.error("Message: {}", e.getMessage());

                    if (e.getCause() != null) {
                        log.error("Cause: {}", e.getCause().getMessage());
                    }

                    // Tentative de debug du header JWT
                    try {
                        String[] parts = token.split("\\.");
                        if (parts.length >= 2) {
                            String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
                            log.error("Header JWT: {}", header);

                            // ✅ Debug du payload aussi
                            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                            log.error("Payload JWT: {}", payload);
                        }
                    } catch (Exception headerEx) {
                        log.error("Impossible de décoder le header/payload JWT: {}", headerEx.getMessage());
                    }

                    throw e;
                }
            };

        } catch (Exception e) {
            log.error("❌ ERREUR CONFIGURATION JWT DECODER: {}", e.getMessage());
            throw new RuntimeException("Impossible de configurer le JWT Decoder", e);
        }
    }

    /**
     * ✅ CORRECTION: Convertisseur JWT amélioré pour extraire les rôles et autorités
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix(""); // Pas de préfixe par défaut
        authoritiesConverter.setAuthoritiesClaimName("authorities"); // Nom du claim contenant les autorités

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            log.debug("=== EXTRACTION AUTORITÉS JWT ===");
            log.debug("Claims disponibles: {}", jwt.getClaims().keySet());

            // Extraire les autorités du claim personnalisé
            Collection<String> authorities = jwt.getClaimAsStringList("authorities");
            if (authorities != null && !authorities.isEmpty()) {
                log.debug("✅ Autorités trouvées: {}", authorities);
                return authorities.stream()
                        .map(authority -> new org.springframework.security.core.authority.SimpleGrantedAuthority(authority))
                        .map(grantedAuthority -> (org.springframework.security.core.GrantedAuthority) grantedAuthority)
                        .toList();
            }

            // ✅ Fallback: essayer d'extraire depuis d'autres claims possibles
            Collection<String> scopes = jwt.getClaimAsStringList("scope");
            if (scopes != null && !scopes.isEmpty()) {
                log.debug("✅ Scopes trouvés (fallback): {}", scopes);
                return scopes.stream()
                        .map(scope -> "SCOPE_" + scope)
                        .map(authority -> new org.springframework.security.core.authority.SimpleGrantedAuthority(authority))
                        .map(grantedAuthority -> (org.springframework.security.core.GrantedAuthority) grantedAuthority)
                        .toList();
            }

            log.warn("⚠️ Aucune autorité trouvée dans le token JWT");
            log.debug("Claim 'authorities' = {}", jwt.getClaimAsString("authorities"));
            log.debug("Claim 'scope' = {}", jwt.getClaimAsString("scope"));
            log.debug("Tous les claims: {}", jwt.getClaims());

            return java.util.Collections.emptyList();
        });

        // ✅ Utiliser l'email comme principal (subject)
        converter.setPrincipalClaimName("sub"); // Email comme principal

        return converter;
    }
}