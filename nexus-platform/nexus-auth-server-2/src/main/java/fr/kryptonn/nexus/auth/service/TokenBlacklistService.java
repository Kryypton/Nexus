package fr.kryptonn.nexus.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;
    private final JwtService jwtService;

    private static final String BLACKLIST_PREFIX = "blacklist:";
    private static final String USER_BLACKLIST_PREFIX = "user_blacklist:";

    public void blacklistToken(String token, String reason) {
        try {
            if (!jwtService.validateToken(token)) {
                log.warn("Tentative de blacklist d'un token invalide");
                return;
            }

            String jti = jwtService.extractJti(token);
            String email = jwtService.extractEmail(token);
            Date expiration = jwtService.extractExpiration(token);

            long ttlSeconds = (expiration.getTime() - System.currentTimeMillis()) / 1000;

            if (ttlSeconds > 0) {
                String blacklistKey = BLACKLIST_PREFIX + jti;
                String blacklistValue = String.format("email:%s,reason:%s,time:%s",
                        email, reason != null ? reason : "Manual logout", Instant.now());

                redisTemplate.opsForValue().set(
                        blacklistKey,
                        blacklistValue,
                        Duration.ofSeconds(ttlSeconds)
                );

                log.info("Token blacklisted pour l'utilisateur: {} (JTI: {}, TTL: {}s)",
                        email, jti, ttlSeconds);
            }

        } catch (Exception e) {
            log.error("Erreur lors de la mise en blacklist du token: {}", e.getMessage());
            throw new RuntimeException("Impossible de blacklister le token", e);
        }
    }

    public boolean isTokenBlacklisted(String token) {
        try {
            String jti = jwtService.extractJti(token);
            String blacklistKey = BLACKLIST_PREFIX + jti;

            return Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey));
        } catch (Exception e) {
            log.warn("Erreur lors de la vérification de blacklist: {}", e.getMessage());
            return true;
        }
    }

    public boolean isJtiBlacklisted(String jti) {
        try {
            String blacklistKey = BLACKLIST_PREFIX + jti;
            return Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey));
        } catch (Exception e) {
            log.warn("Erreur lors de la vérification de blacklist par JTI: {}", e.getMessage());
            return true;
        }
    }

    public void blacklistAllUserTokens(String userEmail, String reason) {
        try {
            String userBlacklistKey = USER_BLACKLIST_PREFIX + userEmail;
            String timestamp = Instant.now().toString();

            redisTemplate.opsForValue().set(
                    userBlacklistKey,
                    String.format("reason:%s,time:%s", reason, timestamp),
                    Duration.ofDays(8)
            );

            log.info("Tous les tokens révoqués pour l'utilisateur: {} - raison: {}", userEmail, reason);
        } catch (Exception e) {
            log.error("Erreur lors de la révocation de tous les tokens pour {}: {}", userEmail, e.getMessage());
            throw new RuntimeException("Impossible de révoquer tous les tokens", e);
        }
    }

    public boolean areAllUserTokensRevoked(String userEmail, Date tokenIssuedAt) {
        try {
            String userBlacklistKey = USER_BLACKLIST_PREFIX + userEmail;
            String revocationInfo = redisTemplate.opsForValue().get(userBlacklistKey);

            if (revocationInfo == null) {
                return false;
            }

            String[] parts = revocationInfo.split(",");
            for (String part : parts) {
                if (part.startsWith("time:")) {
                    String revocationTime = part.substring(5);
                    Instant revoked = Instant.parse(revocationTime);
                    Instant issued = tokenIssuedAt.toInstant();

                    return issued.isBefore(revoked) || issued.equals(revoked);
                }
            }

            return false;
        } catch (Exception e) {
            log.warn("Erreur lors de la vérification de révocation utilisateur: {}", e.getMessage());
            return false;
        }
    }

    public void removeFromBlacklist(String jti) {
        try {
            String blacklistKey = BLACKLIST_PREFIX + jti;
            redisTemplate.delete(blacklistKey);
            log.info("Token retiré de la blacklist: {}", jti);
        } catch (Exception e) {
            log.error("Erreur lors de la suppression de blacklist: {}", e.getMessage());
        }
    }

    @Scheduled(fixedRate = 3600000) // 1 heure
    public void cleanupBlacklistStats() {
        try {
            Set<String> blacklistKeys = redisTemplate.keys(BLACKLIST_PREFIX + "*");
            Set<String> userBlacklistKeys = redisTemplate.keys(USER_BLACKLIST_PREFIX + "*");

            int totalBlacklistedTokens = blacklistKeys != null ? blacklistKeys.size() : 0;
            int totalRevokedUsers = userBlacklistKeys != null ? userBlacklistKeys.size() : 0;

            log.debug("Statistiques blacklist - Tokens: {}, Utilisateurs révoqués: {}",
                    totalBlacklistedTokens, totalRevokedUsers);
        } catch (Exception e) {
            log.error("Erreur lors du nettoyage des statistiques: {}", e.getMessage());
        }
    }

    public String getBlacklistInfo(String jti) {
        try {
            String blacklistKey = BLACKLIST_PREFIX + jti;
            return redisTemplate.opsForValue().get(blacklistKey);
        } catch (Exception e) {
            log.warn("Erreur lors de la récupération des infos blacklist: {}", e.getMessage());
            return null;
        }
    }

    public long getBlacklistedTokenCount() {
        try {
            Set<String> keys = redisTemplate.keys(BLACKLIST_PREFIX + "*");
            return keys != null ? keys.size() : 0;
        } catch (Exception e) {
            log.warn("Erreur lors du comptage des tokens blacklistés: {}", e.getMessage());
            return 0;
        }
    }
}