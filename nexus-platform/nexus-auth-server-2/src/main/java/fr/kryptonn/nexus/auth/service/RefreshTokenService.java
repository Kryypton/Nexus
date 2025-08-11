package fr.kryptonn.nexus.auth.service;

import fr.kryptonn.nexus.auth.entity.RefreshToken;
import fr.kryptonn.nexus.auth.entity.User;
import fr.kryptonn.nexus.auth.exception.TokenRefreshException;
import fr.kryptonn.nexus.auth.repository.RefreshTokenRepository;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService userService;
    private final SecureRandom secureRandom = new SecureRandom();

    @Getter
    @Value("${app.jwt.refresh-expiration-ms:604800000}")
    private long refreshTokenExpirationMs;

    public RefreshToken generateRefreshToken(String userEmail) {
        try {
            User user = userService.findByEmail(userEmail);

            refreshTokenRepository.deleteByUser(user);

            String tokenValue = generateSecureToken();

            RefreshToken refreshToken = RefreshToken.builder()
                    .user(user)
                    .token(tokenValue)
                    .expiryDate(Instant.now().plusMillis(refreshTokenExpirationMs))
                    .build();

            RefreshToken saved = refreshTokenRepository.save(refreshToken);
            log.info("Refresh token généré pour l'utilisateur: {}", userEmail);

            return saved;
        } catch (Exception e) {
            log.error("Erreur lors de la génération du refresh token pour {}: {}", userEmail, e.getMessage());
            throw new RuntimeException("Impossible de générer le refresh token", e);
        }
    }

    public RefreshToken validateAndRetrieve(String token) {
        Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findByToken(token);

        if (refreshTokenOpt.isEmpty()) {
            log.warn("Refresh token non trouvé: {}", token.substring(0, Math.min(token.length(), 10)) + "...");
            throw new TokenRefreshException("Refresh token introuvable");
        }

        RefreshToken refreshToken = refreshTokenOpt.get();

        if (refreshToken.isExpired()) {
            log.warn("Refresh token expiré pour l'utilisateur: {}", refreshToken.getUser().getEmail());
            refreshTokenRepository.delete(refreshToken);
            throw new TokenRefreshException("Refresh token expiré. Veuillez vous reconnecter");
        }

        return refreshToken;
    }

    public RefreshToken rotateRefreshToken(RefreshToken existingToken) {
        try {
            User user = existingToken.getUser();

            refreshTokenRepository.delete(existingToken);
            log.debug("Ancien refresh token supprimé pour: {}", user.getEmail());

            String newTokenValue = generateSecureToken();

            RefreshToken newRefreshToken = RefreshToken.builder()
                    .user(user)
                    .token(newTokenValue)
                    .expiryDate(Instant.now().plusMillis(refreshTokenExpirationMs))
                    .build();

            RefreshToken saved = refreshTokenRepository.save(newRefreshToken);
            log.info("Refresh token rotation effectuée pour: {}", user.getEmail());

            return saved;
        } catch (Exception e) {
            log.error("Erreur lors de la rotation du refresh token: {}", e.getMessage());
            throw new RuntimeException("Impossible de faire la rotation du token", e);
        }
    }

    public void deleteRefreshToken(RefreshToken refreshToken) {
        try {
            refreshTokenRepository.delete(refreshToken);
            log.info("Refresh token supprimé pour: {}", refreshToken.getUser().getEmail());
        } catch (Exception e) {
            log.error("Erreur lors de la suppression du refresh token: {}", e.getMessage());
        }
    }

    public void deleteAllUserRefreshTokens(String userEmail) {
        try {
            User user = userService.findByEmail(userEmail);
            int deletedCount = refreshTokenRepository.deleteByUser(user);
            log.info("Suppression de {} refresh tokens pour l'utilisateur: {}", deletedCount, userEmail);
        } catch (Exception e) {
            log.error("Erreur lors de la suppression des refresh tokens pour {}: {}", userEmail, e.getMessage());
        }
    }

    public void deleteAllUserRefreshTokensByUserId(Long userId) {
        try {
            User user = userService.findById(userId);
            deleteAllUserRefreshTokens(user.getEmail());
        } catch (Exception e) {
            log.error("Erreur lors de la suppression des refresh tokens pour l'ID {}: {}", userId, e.getMessage());
        }
    }

    public boolean hasValidRefreshToken(String userEmail) {
        try {
            User user = userService.findByEmail(userEmail);
            Optional<RefreshToken> tokenOpt = refreshTokenRepository.findByUser(user);

            if (tokenOpt.isEmpty()) {
                return false;
            }

            RefreshToken token = tokenOpt.get();
            if (token.isExpired()) {
                refreshTokenRepository.delete(token);
                return false;
            }

            return true;
        } catch (Exception e) {
            log.warn("Erreur lors de la vérification du refresh token pour {}: {}", userEmail, e.getMessage());
            return false;
        }
    }

    @Transactional
    public void cleanupExpiredTokens() {
        try {
            int deletedCount = refreshTokenRepository.deleteByExpiryDateBefore(Instant.now());
            if (deletedCount > 0) {
                log.info("Nettoyage automatique: {} refresh tokens expirés supprimés", deletedCount);
            }
        } catch (Exception e) {
            log.error("Erreur lors du nettoyage des refresh tokens expirés: {}", e.getMessage());
        }
    }


    private String generateSecureToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public long getActiveRefreshTokenCount() {
        try {
            return refreshTokenRepository.countByExpiryDateAfter(Instant.now());
        } catch (Exception e) {
            log.warn("Erreur lors du comptage des refresh tokens actifs: {}", e.getMessage());
            return 0;
        }
    }

    public Optional<RefreshToken> getActiveRefreshTokenForUser(String userEmail) {
        try {
            User user = userService.findByEmail(userEmail);
            Optional<RefreshToken> tokenOpt = refreshTokenRepository.findByUser(user);

            if (tokenOpt.isPresent() && !tokenOpt.get().isExpired()) {
                return tokenOpt;
            }

            tokenOpt.ifPresent(refreshTokenRepository::delete);
            return Optional.empty();
        } catch (Exception e) {
            log.warn("Erreur lors de la récupération du refresh token actif pour {}: {}", userEmail, e.getMessage());
            return Optional.empty();
        }
    }
}