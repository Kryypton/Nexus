package fr.kryptonn.nexus.auth.repository;

import fr.kryptonn.nexus.auth.entity.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Repository
public interface RevokedTokenRepository extends JpaRepository<RevokedToken, String> {

    boolean existsByTokenHash(String tokenHash);

    /**
     * ✅ Correction : Ajout de @Transactional pour les opérations de modification
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM RevokedToken rt WHERE rt.expiryDate < :now")
    int deleteExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * ✅ Correction : Ajout de @Transactional pour les opérations de suppression
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM RevokedToken rt WHERE rt.userEmail = :userEmail")
    int deleteByUserEmail(@Param("userEmail") String userEmail);

    /**
     * ✅ Méthode helper pour nettoyer les tokens expirés
     */
    @Modifying
    @Transactional
    default int cleanupExpiredTokens() {
        return deleteExpiredTokens(LocalDateTime.now());
    }

    /**
     * ✅ Méthode pour compter les tokens expirés avant suppression
     */
    @Query("SELECT COUNT(rt) FROM RevokedToken rt WHERE rt.expiryDate < :now")
    long countExpiredTokens(@Param("now") LocalDateTime now);
}