package fr.kryptonn.nexus.auth.repository;

import fr.kryptonn.nexus.auth.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> { // ✅ Changé de String à Long

    /**
     * Trouve un utilisateur par email avec ses autorités
     */
    @EntityGraph(attributePaths = "authorities")
    Optional<User> findByEmail(String email);

    /**
     * Vérifie l'existence par email
     */
    boolean existsByEmail(String email);

    /**
     * Trouve un utilisateur par email avec chargement explicite des autorités
     */
    @Query("SELECT DISTINCT u FROM User u " +
            "LEFT JOIN FETCH u.authorities " +
            "WHERE u.email = :email")
    Optional<User> findByEmailWithAuthorities(@Param("email") String email);

    /**
     * Récupère tous les utilisateurs actifs
     */
    @Query("SELECT u FROM User u WHERE u.enabled = true")
    List<User> findAllEnabledUsers();

    /**
     * Compte les utilisateurs actifs
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.enabled = true")
    long countEnabledUsers();

    /**
     * Trouve les utilisateurs par autorité
     */
    @Query("SELECT DISTINCT u FROM User u " +
            "JOIN u.authorities a " +
            "WHERE a.authority = :authority")
    List<User> findByAuthority(@Param("authority") String authority);

    Optional<User> findByDiscordAccount_Id(String discordId);

    Optional<User> findByBattleNetAccount_Id(String battleNetId);

    List<User> findByDiscordAccount_RefreshTokenIsNotNull();

    /**
     * ✅ Remplacé la requête native par JPQL pour éviter les problèmes de requête de comptage
     * Trouve les utilisateurs créés récemment (dernières 24h)
     */
    @Query("SELECT u FROM User u WHERE u.createdAt >= :since")
    List<User> findRecentUsers(@Param("since") java.time.LocalDateTime since);

    /**
     * ✅ Méthode helper pour récupérer les utilisateurs des dernières 24h
     */
    default List<User> findUsersFromLast24Hours() {
        return findRecentUsers(java.time.LocalDateTime.now().minusDays(1));
    }
}