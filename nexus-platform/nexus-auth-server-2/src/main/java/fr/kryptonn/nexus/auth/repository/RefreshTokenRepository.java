package fr.kryptonn.nexus.auth.repository;

import fr.kryptonn.nexus.auth.entity.RefreshToken;
import fr.kryptonn.nexus.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUser(User user);

    @Modifying
    @Transactional
    int deleteByUser(User user);

    /**
     * ✅ Correction : Ajout de @Transactional pour les opérations de modification
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now")
    int deleteByExpiryDateBefore(@Param("now") Instant now);

    /**
     * ✅ Requête de comptage pour éviter les problèmes avec la pagination
     */
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.expiryDate > :now")
    long countByExpiryDateAfter(@Param("now") Instant now);

    /**
     * ✅ Requête d'existence optimisée
     */
    @Query("SELECT CASE WHEN COUNT(rt) > 0 THEN true ELSE false END " +
            "FROM RefreshToken rt WHERE rt.user = :user AND rt.expiryDate > :now")
    boolean existsByUserAndExpiryDateAfter(@Param("user") User user, @Param("now") Instant now);

    /**
     * ✅ Méthode helper pour nettoyer les tokens expirés
     */
    @Modifying
    @Transactional
    default int cleanupExpiredTokens() {
        return deleteByExpiryDateBefore(Instant.now());
    }
}