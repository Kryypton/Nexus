package fr.kryptonn.nexus.auth.controller;

import fr.kryptonn.nexus.auth.dto.*;
import fr.kryptonn.nexus.auth.entity.User;
import fr.kryptonn.nexus.auth.service.AuthenticationService;
import fr.kryptonn.nexus.auth.service.JwtService;
import fr.kryptonn.nexus.auth.service.TokenBlacklistService;
import fr.kryptonn.nexus.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

/**
 * Contrôleur d'authentification refactorisé
 * Utilise les services séparés et corrige les problèmes de logique
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Validated
@Slf4j
public class AuthController {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;
    private final UserService userService;
    private final TokenBlacklistService tokenBlacklistService;

    /**
     * Inscription d'un nouvel utilisateur
     */
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<UserResponseDto>> register(@Valid @RequestBody RegisterUserDto registerDto) {
        log.info("Tentative d'inscription pour l'email: {}", registerDto.getEmail());

        try {
            User registeredUser = authenticationService.signup(registerDto);
            UserResponseDto response = UserResponseDto.fromUser(registeredUser);

            log.info("Inscription réussie pour l'utilisateur: {}", registeredUser.getEmail());

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.success("Utilisateur créé avec succès", response));

        } catch (Exception e) {
            log.error("Erreur lors de l'inscription pour {}: {}", registerDto.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(e.getMessage()));
        }
    }

    /**
     * Connexion d'un utilisateur avec génération de tokens
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> authenticate(@Valid @RequestBody LoginUserDto loginDto) {
        log.info("Tentative de connexion pour l'email: {}", loginDto.getEmail());

        try {
            // Authentifier l'utilisateur
            User authenticatedUser = authenticationService.authenticate(loginDto);

            // Générer la paire de tokens
            AuthenticationService.TokenPair tokenPair =
                    authenticationService.generateTokenPair(authenticatedUser.getEmail());

            // Construire la réponse
            LoginResponse loginResponse = LoginResponse.builder()
                    .token(tokenPair.getAccessToken())
                    .refreshToken(tokenPair.getRefreshToken())
                    .expiresIn(tokenPair.getAccessTokenExpiresIn())
                    .tokenType("Bearer")
                    .user(UserResponseDto.fromUser(authenticatedUser))
                    .build();

            log.info("Connexion réussie pour l'utilisateur: {}", authenticatedUser.getEmail());

            return ResponseEntity.ok(ApiResponse.success("Connexion réussie", loginResponse));

        } catch (Exception e) {
            log.error("Erreur lors de la connexion pour {}: {}", loginDto.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Échec de l'authentification"));
        }
    }

    /**
     * Rafraîchissement des tokens - CORRIGÉ
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<LoginResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Tentative de rafraîchissement de token");

        try {
            // Utiliser le service d'authentification pour le refresh
            AuthenticationService.TokenPair newTokenPair =
                    authenticationService.refreshTokens(request.getRefreshToken());

            // Récupérer les infos utilisateur depuis le nouveau token
            String userEmail = jwtService.extractEmail(newTokenPair.getAccessToken());
            UserResponseDto userDto = userService.getUserByEmail(userEmail);

            LoginResponse response = LoginResponse.builder()
                    .token(newTokenPair.getAccessToken())
                    .refreshToken(newTokenPair.getRefreshToken())
                    .expiresIn(newTokenPair.getAccessTokenExpiresIn())
                    .tokenType("Bearer")
                    .user(userDto)
                    .build();

            log.info("Token rafraîchi avec succès pour l'utilisateur: {}", userEmail);
            return ResponseEntity.ok(ApiResponse.success("Token rafraîchi", response));

        } catch (Exception e) {
            log.error("Erreur lors du rafraîchissement du token: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(ApiResponse.error("Impossible de rafraîchir le token"));
        }
    }

    /**
     * Déconnexion avec blacklist - CORRIGÉ
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<LogoutResponse>> logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        try {
            String userEmail = null;

            // Récupérer l'email de l'utilisateur connecté
            if (authentication != null && authentication.isAuthenticated()) {
                userEmail = authentication.getName(); // Email depuis le token
            }

            // Traiter le token s'il est fourni
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                // Si pas d'email depuis l'auth, l'extraire du token
                if (userEmail == null) {
                    try {
                        userEmail = jwtService.extractEmail(token);
                    } catch (Exception e) {
                        log.warn("Impossible d'extraire l'email du token: {}", e.getMessage());
                    }
                }

                // Déconnexion avec blacklist
                if (userEmail != null) {
                    authenticationService.logout(token, userEmail, "User logout");
                }
            } else if (userEmail != null) {
                // Déconnexion sans token (supprimer juste les refresh tokens)
                authenticationService.logout(null, userEmail, "User logout");
            }

            LogoutResponse response = LogoutResponse.builder()
                    .message("Déconnexion réussie")
                    .timestamp(LocalDateTime.now())
                    .build();

            log.info("Déconnexion réussie pour l'utilisateur: {}", userEmail);
            return ResponseEntity.ok(ApiResponse.success(response));

        } catch (Exception e) {
            log.error("Erreur lors de la déconnexion: {}", e.getMessage());

            // Retourner succès même en cas d'erreur (déconnexion côté client)
            LogoutResponse response = LogoutResponse.builder()
                    .message("Déconnexion effectuée")
                    .timestamp(LocalDateTime.now())
                    .build();

            return ResponseEntity.ok(ApiResponse.success(response));
        }
    }

    /**
     * Déconnexion de tous les appareils
     */
    @PostMapping("/logout-all")
    public ResponseEntity<ApiResponse<LogoutResponse>> logoutFromAllDevices(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Non authentifié"));
        }

        try {
            String userEmail = authentication.getName();
            authenticationService.logoutFromAllDevices(userEmail, "Logout from all devices");

            LogoutResponse response = LogoutResponse.builder()
                    .message("Déconnexion de tous les appareils réussie")
                    .timestamp(LocalDateTime.now())
                    .build();

            log.info("Déconnexion globale réussie pour l'utilisateur: {}", userEmail);
            return ResponseEntity.ok(ApiResponse.success(response));

        } catch (Exception e) {
            log.error("Erreur lors de la déconnexion globale: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de la déconnexion"));
        }
    }

    /**
     * Récupère les informations de l'utilisateur connecté
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponseDto>> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Non authentifié"));
        }

        try {
            String userEmail = authentication.getName();
            log.debug("Récupération des informations pour l'utilisateur: {}", userEmail);

            UserResponseDto currentUser = userService.getUserByEmail(userEmail);
            return ResponseEntity.ok(ApiResponse.success(currentUser));

        } catch (Exception e) {
            log.error("Erreur lors de la récupération des infos utilisateur: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de la récupération des informations"));
        }
    }

    /**
     * Version simplifiée pour vérifier l'authentification
     */
    @GetMapping("/me/simple")
    public ResponseEntity<ApiResponse<String>> getCurrentUserSimple(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Utilisateur non authentifié"));
        }

        String userEmail = authentication.getName();
        return ResponseEntity.ok(
                ApiResponse.success("Utilisateur connecté: " + userEmail)
        );
    }

    /**
     * Validation d'un token
     */
    @PostMapping("/validate-token")
    public ResponseEntity<ApiResponse<TokenValidationResponse>> validateToken(
            @Valid @RequestBody TokenValidationRequest request) {
        try {
            boolean isValid = authenticationService.isTokenValid(request.getToken());
            String userEmail = null;
            boolean isExpired = true;

            if (isValid) {
                userEmail = jwtService.extractEmail(request.getToken());
                isExpired = jwtService.isTokenExpired(request.getToken());
            }

            TokenValidationResponse response = TokenValidationResponse.builder()
                    .valid(isValid && !isExpired)
                    .username(userEmail)
                    .expired(isExpired)
                    .message(isValid ? "Token valide" : "Token invalide")
                    .build();

            return ResponseEntity.ok(ApiResponse.success(response));

        } catch (Exception e) {
            log.warn("Erreur lors de la validation du token: {}", e.getMessage());

            TokenValidationResponse response = TokenValidationResponse.builder()
                    .valid(false)
                    .expired(true)
                    .message("Token invalide")
                    .build();

            return ResponseEntity.ok(ApiResponse.success(response));
        }
    }

    /**
     * Health check de l'API d'authentification
     */
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> health() {
        return ResponseEntity.ok(
                ApiResponse.success("Auth Server is running")
        );
    }

    /**
     * Statistiques d'authentification (admin uniquement)
     */
    @GetMapping("/stats")
    public ResponseEntity<ApiResponse<AuthStatsResponse>> getAuthStats(Authentication authentication) {
        // Note: Ajouter @PreAuthorize("hasRole('ADMIN')") si nécessaire

        try {
            long totalUsers = userService.getTotalUserCount();
            long activeUsers = userService.getActiveUserCount();
            long blacklistedTokens = tokenBlacklistService.getBlacklistedTokenCount();

            AuthStatsResponse stats = AuthStatsResponse.builder()
                    .totalUsers(totalUsers)
                    .activeUsers(activeUsers)
                    .blacklistedTokens(blacklistedTokens)
                    .build();

            return ResponseEntity.ok(ApiResponse.success(stats));

        } catch (Exception e) {
            log.error("Erreur lors de la récupération des statistiques: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Erreur lors de la récupération des statistiques"));
        }
    }

    /**
     * DTO pour les statistiques d'authentification
     */
    @lombok.Builder
    @lombok.Data
    public static class AuthStatsResponse {
        private long totalUsers;
        private long activeUsers;
        private long blacklistedTokens;
    }
}