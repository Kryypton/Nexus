package fr.kryptonn.nexus.axon.controller;

import fr.kryptonn.nexus.axon.dto.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Contrôleur de test pour l'authentification
 */
@RestController
@RequestMapping("/api")
@Slf4j
public class TestController {

    /**
     * Endpoint public pour tester que l'application fonctionne
     */
    @GetMapping("/public/health")
    public ResponseEntity<ApiResponse<Map<String, Object>>> publicHealth() {
        log.info("=== PUBLIC HEALTH ENDPOINT CALLED ===");

        Map<String, Object> data = new HashMap<>();
        data.put("status", "UP");
        data.put("application", "Nexus Axon Application");
        data.put("version", "1.0.0");
        data.put("timestamp", LocalDateTime.now());

        log.info("=== PUBLIC HEALTH RESPONSE READY ===");
        return ResponseEntity.ok(ApiResponse.success("Application en fonctionnement", data));
    }

    /**
     * Endpoint protégé - nécessite une authentification
     */
    @GetMapping("/protected/user-info")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUserInfo(
            Authentication authentication,
            HttpServletRequest request) {

        log.info("=== PROTECTED USER-INFO ENDPOINT CALLED ===");

        // Vérification immédiate de l'authentification
        if (authentication == null) {
            log.error("Authentication is null!");
            return ResponseEntity.status(401)
                    .body(ApiResponse.error("Authentication is null"));
        }

        if (!authentication.isAuthenticated()) {
            log.error("User is not authenticated!");
            return ResponseEntity.status(401)
                    .body(ApiResponse.error("User is not authenticated"));
        }

        log.info("Authentication successful for user: {}", authentication.getName());

        Map<String, Object> data = new HashMap<>();
        data.put("user", authentication.getName());
        data.put("authorities", authentication.getAuthorities());
        data.put("authType", authentication.getClass().getSimpleName());
        data.put("timestamp", LocalDateTime.now());

        // Informations supplémentaires du JWT si disponibles
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            log.info("JWT Principal detected");

            Map<String, Object> jwtInfo = new HashMap<>();
            jwtInfo.put("issuer", jwt.getIssuer() != null ? jwt.getIssuer().toString() : null);
            jwtInfo.put("subject", jwt.getSubject());
            jwtInfo.put("expiration", jwt.getExpiresAt());
            jwtInfo.put("issuedAt", jwt.getIssuedAt());
            jwtInfo.put("audience", jwt.getAudience());

            data.put("jwt", jwtInfo);

            // Log des claims pour debug
            log.debug("JWT Claims: {}", jwt.getClaims());
        } else {
            log.info("Principal type: {}", authentication.getPrincipal().getClass());
        }

        // Log du header Authorization pour debug
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null) {
            log.debug("Authorization header present: {}",
                    authHeader.length() > 20 ? authHeader.substring(0, 20) + "..." : authHeader);
        } else {
            log.warn("No Authorization header found");
        }

        log.info("=== RETURNING USER INFO RESPONSE ===");
        return ResponseEntity.ok(ApiResponse.success("Accès autorisé à l'endpoint protégé", data));
    }

    /**
     * Endpoint admin - nécessite le rôle ADMIN
     */
    @GetMapping("/admin/system-info")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getSystemInfo(Authentication authentication) {
        log.info("=== ADMIN ENDPOINT CALLED ===");
        log.info("Admin endpoint called by: {}", authentication.getName());

        Map<String, Object> data = new HashMap<>();
        data.put("user", authentication.getName());
        data.put("authorities", authentication.getAuthorities());
        data.put("timestamp", LocalDateTime.now());
        data.put("systemInfo", Map.of(
                "javaVersion", System.getProperty("java.version"),
                "osName", System.getProperty("os.name"),
                "availableProcessors", Runtime.getRuntime().availableProcessors(),
                "maxMemory", Runtime.getRuntime().maxMemory() / 1024 / 1024 + " MB"
        ));

        return ResponseEntity.ok(ApiResponse.success("Accès autorisé à l'endpoint admin", data));
    }

    /**
     * Endpoint pour tester les différents rôles
     */
    @GetMapping("/protected/role-test")
    public ResponseEntity<ApiResponse<Map<String, Object>>> testRoles(Authentication authentication) {
        log.info("=== ROLE TEST ENDPOINT CALLED ===");

        Map<String, Object> data = new HashMap<>();
        data.put("user", authentication.getName());
        data.put("authorities", authentication.getAuthorities());
        data.put("timestamp", LocalDateTime.now());

        boolean hasUserRole = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_USER"));
        boolean hasAdminRole = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));

        data.put("hasUserRole", hasUserRole);
        data.put("hasAdminRole", hasAdminRole);

        log.info("User {} - ROLE_USER: {}, ROLE_ADMIN: {}",
                authentication.getName(), hasUserRole, hasAdminRole);

        return ResponseEntity.ok(ApiResponse.success("Test des rôles effectué", data));
    }
}