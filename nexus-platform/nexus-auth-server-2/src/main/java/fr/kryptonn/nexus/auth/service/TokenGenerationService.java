package fr.kryptonn.nexus.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Service générique de génération de tokens aléatoires sécurisés
 * Réutilisable pour différentes fonctionnalités (vérification email, reset password, etc.)
 */
@Service
@Slf4j
public class TokenGenerationService {

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Génère un token UUID simple
     */
    public String generateUuidToken() {
        return UUID.randomUUID().toString();
    }

    /**
     * Génère un token sécurisé de longueur spécifiée (en octets)
     */
    public String generateSecureToken(int lengthInBytes) {
        byte[] randomBytes = new byte[lengthInBytes];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Génère un token sécurisé de 32 octets (256 bits) par défaut
     */
    public String generateSecureToken() {
        return generateSecureToken(32);
    }

    /**
     * Génère un token alphanumérique de longueur spécifiée
     */
    public String generateAlphanumericToken(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder token = new StringBuilder();

        for (int i = 0; i < length; i++) {
            int index = secureRandom.nextInt(chars.length());
            token.append(chars.charAt(index));
        }

        return token.toString();
    }

    /**
     * Génère un token numérique de longueur spécifiée
     */
    public String generateNumericToken(int length) {
        StringBuilder token = new StringBuilder();

        for (int i = 0; i < length; i++) {
            token.append(secureRandom.nextInt(10));
        }

        return token.toString();
    }

    /**
     * Génère un token avec préfixe et timestamp
     */
    public String generateTokenWithPrefix(String prefix) {
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        String randomPart = generateSecureToken(16);
        return prefix + "_" + timestamp + "_" + randomPart;
    }

    /**
     * Génère un token de vérification d'email (32 caractères alphanumériques)
     */
    public String generateEmailVerificationToken() {
        return generateAlphanumericToken(32);
    }

    /**
     * Génère un token de reset de mot de passe (UUID + partie sécurisée)
     */
    public String generatePasswordResetToken() {
        return generateTokenWithPrefix("PWD");
    }

    /**
     * Génère un code de vérification numérique (pour SMS, etc.)
     */
    public String generateVerificationCode() {
        return generateNumericToken(6);
    }

    /**
     * Valide qu'un token a le format attendu
     */
    public boolean isValidTokenFormat(String token, TokenType type) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }

        return switch (type) {
            case UUID -> isValidUuid(token);
            case ALPHANUMERIC_32 -> token.matches("^[A-Z0-9]{32}$");
            case NUMERIC_6 -> token.matches("^\\d{6}$");
            case SECURE_BASE64 -> isValidBase64Token(token);
            case WITH_PREFIX -> token.contains("_") && token.split("_").length >= 3;
        };
    }

    private boolean isValidUuid(String token) {
        try {
            UUID.fromString(token);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private boolean isValidBase64Token(String token) {
        try {
            Base64.getUrlDecoder().decode(token);
            return token.length() >= 16; // Au moins 16 caractères
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Types de tokens supportés
     */
    public enum TokenType {
        UUID,
        ALPHANUMERIC_32,
        NUMERIC_6,
        SECURE_BASE64,
        WITH_PREFIX
    }

    /**
     * Génère un token selon le type spécifié
     */
    public String generateToken(TokenType type) {
        return switch (type) {
            case UUID -> generateUuidToken();
            case ALPHANUMERIC_32 -> generateEmailVerificationToken();
            case NUMERIC_6 -> generateVerificationCode();
            case SECURE_BASE64 -> generateSecureToken();
            case WITH_PREFIX -> generateTokenWithPrefix("GEN");
        };
    }

    /**
     * Hash un token pour stockage sécurisé (optionnel)
     */
    public String hashToken(String token) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            log.error("Erreur lors du hashage du token: {}", e.getMessage());
            throw new RuntimeException("Impossible de hasher le token", e);
        }
    }
}