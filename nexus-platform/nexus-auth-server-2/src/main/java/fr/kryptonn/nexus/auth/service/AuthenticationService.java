package fr.kryptonn.nexus.auth.service;

import fr.kryptonn.nexus.auth.dto.LoginUserDto;
import fr.kryptonn.nexus.auth.dto.RegisterUserDto;
import fr.kryptonn.nexus.auth.entity.RefreshToken;
import fr.kryptonn.nexus.auth.entity.User;
import fr.kryptonn.nexus.auth.entity.UserStatePhase;
import fr.kryptonn.nexus.auth.exception.AuthenticationException;
import fr.kryptonn.nexus.auth.exception.ResourceNotFoundException;
import fr.kryptonn.nexus.auth.exception.TokenRefreshException;
import fr.kryptonn.nexus.auth.exception.UserAlreadyExistsException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZoneId;
import java.util.Date;

/**
 * Service d'authentification refactorisé avec séparation claire des responsabilités
 * Utilise les services spécialisés pour JWT, refresh tokens et blacklist
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthenticationService {

    private final UserService userService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    /**
     * Inscription d'un nouvel utilisateur
     */
    public User signup(RegisterUserDto input) {
        log.info("Tentative d'inscription pour l'email: {}", input.getEmail());

        // Vérification de l'existence de l'utilisateur par email (unique identifiant)
        if (userService.existsByEmail(input.getEmail())) {
            throw new UserAlreadyExistsException(
                    "Un utilisateur avec l'email " + input.getEmail() + " existe déjà");
        }

        // Création de l'utilisateur avec email comme identifiant unique
        User user = User.builder()
                .email(input.getEmail()) // Email = identifiant principal
                .password(passwordEncoder.encode(input.getPassword()))
                .statePhase(UserStatePhase.INITIAL)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        // Attribution du rôle USER par défaut
        user.addAuthority("ROLE_USER");

        User savedUser = userService.save(user);
        log.info("Nouvel utilisateur créé avec l'email: {}", savedUser.getEmail());

        return savedUser;
    }

    /**
     * Authentification d'un utilisateur
     */
    public User authenticate(LoginUserDto input) {
        log.info("Tentative de connexion pour l'email: {}", input.getEmail());

        try {
            // Authentification avec email uniquement
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            input.getEmail(), // Email comme username
                            input.getPassword()
                    )
            );

            User user = userService.findByEmail(input.getEmail());
            log.info("Connexion réussie pour l'utilisateur: {}", user.getEmail());

            return user;

        } catch (BadCredentialsException e) {
            log.warn("Tentative de connexion échouée pour l'email: {}", input.getEmail());
            throw new AuthenticationException("Email ou mot de passe invalide");
        }
    }

    /**
     * Génère une paire de tokens (access + refresh)
     */
    public TokenPair generateTokenPair(String email) {
        try {
            // Générer access token
            String accessToken = jwtService.generateAccessToken(email);

            // Générer refresh token (avec rotation automatique)
            RefreshToken refreshToken = refreshTokenService.generateRefreshToken(email);

            log.debug("Paire de tokens générée pour: {}", email);

            return TokenPair.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken.getToken())
                    .accessTokenExpiresIn(jwtService.getAccessTokenExpirationMs())
                    .refreshTokenExpiresIn(refreshTokenService.getRefreshTokenExpirationMs())
                    .build();

        } catch (Exception e) {
            log.error("Erreur lors de la génération de tokens pour {}: {}", email, e.getMessage());
            throw new RuntimeException("Impossible de générer les tokens", e);
        }
    }

    /**
     * Rafraîchit un access token avec rotation du refresh token
     */
    public TokenPair refreshTokens(String refreshTokenValue) {
        log.info("Tentative de rafraîchissement de token");

        try {
            // Valider le refresh token
            RefreshToken existingRefreshToken = refreshTokenService.validateAndRetrieve(refreshTokenValue);
            String userEmail = existingRefreshToken.getUser().getEmail();

            // Générer nouveau access token
            String newAccessToken = jwtService.generateAccessToken(userEmail);

            // Rotation du refresh token pour sécurité
            RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(existingRefreshToken);

            log.info("Tokens rafraîchis avec succès pour l'utilisateur: {}", userEmail);

            return TokenPair.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken.getToken())
                    .accessTokenExpiresIn(jwtService.getAccessTokenExpirationMs())
                    .refreshTokenExpiresIn(refreshTokenService.getRefreshTokenExpirationMs())
                    .build();

        } catch (TokenRefreshException e) {
            log.warn("Erreur de rafraîchissement: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Erreur lors du rafraîchissement des tokens: {}", e.getMessage());
            throw new TokenRefreshException("Impossible de rafraîchir les tokens");
        }
    }

    /**
     * Déconnexion avec blacklist du token et suppression des refresh tokens
     */
    public void logout(String accessToken, String userEmail, String reason) {
        try {
            // Blacklister l'access token
            if (accessToken != null && !accessToken.isEmpty()) {
                tokenBlacklistService.blacklistToken(accessToken, reason);
            }

            // Supprimer tous les refresh tokens de l'utilisateur
            refreshTokenService.deleteAllUserRefreshTokens(userEmail);

            log.info("Déconnexion réussie pour l'utilisateur: {}", userEmail);

        } catch (Exception e) {
            log.error("Erreur lors de la déconnexion pour {}: {}", userEmail, e.getMessage());
            throw new RuntimeException("Erreur lors de la déconnexion", e);
        }
    }

    /**
     * Déconnexion globale - révoque tous les tokens d'un utilisateur
     */
    public void logoutFromAllDevices(String userEmail, String reason) {
        try {
            // Blacklister tous les futurs tokens de l'utilisateur
            tokenBlacklistService.blacklistAllUserTokens(userEmail, reason);

            // Supprimer tous les refresh tokens
            refreshTokenService.deleteAllUserRefreshTokens(userEmail);

            log.info("Déconnexion globale effectuée pour l'utilisateur: {}", userEmail);

        } catch (Exception e) {
            log.error("Erreur lors de la déconnexion globale pour {}: {}", userEmail, e.getMessage());
            throw new RuntimeException("Erreur lors de la déconnexion globale", e);
        }
    }

    /**
     * Valide un access token en vérifiant la blacklist
     */
    public boolean isTokenValid(String token) {
        try {
            // Vérifier d'abord la signature et l'expiration
            if (!jwtService.validateToken(token)) {
                return false;
            }

            // Vérifier si le token est blacklisté
            if (tokenBlacklistService.isTokenBlacklisted(token)) {
                log.debug("Token blacklisté détecté");
                return false;
            }

            // Vérifier si tous les tokens de l'utilisateur sont révoqués
            String userEmail = jwtService.extractEmail(token);
            Date issuedAt = jwtService.extractIssuedAt(token);
            User user = userService.findByEmail(userEmail);

            if (user.getTokensRevokedAt() != null) {
                if (issuedAt.toInstant().isBefore(user.getTokensRevokedAt().atZone(ZoneId.systemDefault()).toInstant())) {
                    return false;
                }
            }

            return true;

        } catch (Exception e) {
            log.warn("Erreur lors de la validation du token: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Récupère un utilisateur par email
     */
    @Transactional(readOnly = true)
    public User getUserByEmail(String email) {
        return userService.findByEmail(email);
    }

    /**
     * Vérifie si un utilisateur existe par email
     */
    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        return userService.existsByEmail(email);
    }

    /**
     * Classe interne pour représenter une paire de tokens
     */
    @lombok.Builder
    @lombok.Data
    public static class TokenPair {
        private String accessToken;
        private String refreshToken;
        private long accessTokenExpiresIn;
        private long refreshTokenExpiresIn;
    }
}