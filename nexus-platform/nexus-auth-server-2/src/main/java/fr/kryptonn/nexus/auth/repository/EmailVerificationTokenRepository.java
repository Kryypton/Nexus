package fr.kryptonn.nexus.auth.repository;

import fr.kryptonn.nexus.auth.entity.EmailVerificationToken;
import fr.kryptonn.nexus.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, String> {

    /**
     * Trouve un token par sa valeur
     */
    Optional<EmailVerificationToken> findByToken(String token);

    /**
     * Trouve tous les tokens d'un utilisateur
     */
    List<EmailVerificationToken> findByUser(User user);

    /**
     * Trouve tous les tokens d'un utilisateur par email
     */
    List<EmailVerificationToken> findByUserEmail(String userEmail);

    /**
     * Trouve le token valide le plus récent d'un utilisateur
     */
    @Query("SELECT t FROM EmailVerificationToken t WHERE t.user = :user AND t.verified = false AND t.expiryDate > :now ORDER BY t.createdAt DESC")
    Optional<EmailVerificationToken> findLatestValidTokenByUser(@Param("user") User user, @Param("now") Instant now);

    /**
     * Trouve le token valide le plus récent d'un utilisateur par email
     */
    @Query("SELECT t FROM EmailVerificationToken t WHERE t.userEmail = :email AND t.verified = false AND t.expiryDate > :now ORDER BY t.createdAt DESC")
    Optional<EmailVerificationToken> findLatestValidTokenByEmail(@Param("email") String email, @Param("now") Instant now);

    /**
     * Vérifie l'existence d'un token valide pour un utilisateur
     */
    @Query("SELECT CASE WHEN COUNT(t) > 0 THEN true ELSE false END FROM EmailVerificationToken t WHERE t.user = :user AND t.verified = false AND t.expiryDate > :now")
    boolean existsValidTokenForUser(@Param("user") User user, @Param("now") Instant now);

    /**
     * Vérifie l'existence d'un token valide pour un email
     */
    @Query("SELECT CASE WHEN COUNT(t) > 0 THEN true ELSE false END FROM EmailVerificationToken t WHERE t.userEmail = :email AND t.verified = false AND t.expiryDate > :now")
    boolean existsValidTokenForEmail(@Param("email") String email, @Param("now") Instant now);

    /**
     * Supprime tous les tokens expirés
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM EmailVerificationToken t WHERE t.expiryDate < :now")
    int deleteExpiredTokens(@Param("now") Instant now);

    /**
     * Supprime tous les tokens d'un utilisateur
     */
    @Modifying
    @Transactional
    int deleteByUser(User user);

    /**
     * Supprime tous les tokens d'un utilisateur par email
     */
    @Modifying
    @Transactional
    int deleteByUserEmail(String userEmail);

    /**
     * Marque tous les tokens d'un utilisateur comme vérifiés
     */
    @Modifying
    @Transactional
    @Query("UPDATE EmailVerificationToken t SET t.verified = true, t.verifiedAt = :now WHERE t.user = :user AND t.verified = false")
    int markAllUserTokensAsVerified(@Param("user") User user, @Param("now") Instant now);

    /**
     * Compte les tokens expirés
     */
    @Query("SELECT COUNT(t) FROM EmailVerificationToken t WHERE t.expiryDate < :now")
    long countExpiredTokens(@Param("now") Instant now);

    /**
     * Compte les tokens valides pour un utilisateur
     */
    @Query("SELECT COUNT(t) FROM EmailVerificationToken t WHERE t.user = :user AND t.verified = false AND t.expiryDate > :now")
    long countValidTokensForUser(@Param("user") User user, @Param("now") Instant now);

    /**
     * Trouve tous les tokens créés dans une période donnée
     */
    @Query("SELECT t FROM EmailVerificationToken t WHERE t.createdAt BETWEEN :start AND :end")
    List<EmailVerificationToken> findTokensCreatedBetween(@Param("start") Instant start, @Param("end") Instant end);

    /**
     * Méthode helper pour nettoyer les tokens expirés
     */
    @Modifying
    @Transactional
    default int cleanupExpiredTokens() {
        return deleteExpiredTokens(Instant.now());
    }

    /**
     * Méthode helper pour vérifier l'existence d'un token valide maintenant
     */
    default boolean hasValidToken(User user) {
        return existsValidTokenForUser(user, Instant.now());
    }

    /**
     * Méthode helper pour vérifier l'existence d'un token valide par email maintenant
     */
    default boolean hasValidToken(String email) {
        return existsValidTokenForEmail(email, Instant.now());
    }
}