package fr.kryptonn.nexus.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Service de nettoyage automatique
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CleanupService {

    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;

    /**
     * Nettoyage automatique des refresh tokens expirés
     * Toutes les heures
     */
    @Scheduled(fixedRate = 3600000) // 1 heure
    public void cleanupExpiredRefreshTokens() {
        try {
            refreshTokenService.cleanupExpiredTokens();
        } catch (Exception e) {
            log.error("Erreur lors du nettoyage des refresh tokens: {}", e.getMessage());
        }
    }

    /**
     * Nettoyage des statistiques de blacklist
     * Toutes les 4 heures
     */
    @Scheduled(fixedRate = 14400000) // 4 heures
    public void cleanupBlacklistStats() {
        try {
            tokenBlacklistService.cleanupBlacklistStats();
        } catch (Exception e) {
            log.error("Erreur lors du nettoyage des stats blacklist: {}", e.getMessage());
        }
    }
}
