package fr.kryptonn.nexus.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

/**
 * Entité pour stocker les tokens de vérification d'email
 */
@Entity
@Table(name = "email_verification_tokens", indexes = {
        @Index(name = "idx_verification_token", columnList = "token"),
        @Index(name = "idx_user_email", columnList = "user_email"),
        @Index(name = "idx_expiry_date", columnList = "expiry_date"),
        @Index(name = "idx_verified", columnList = "verified")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailVerificationToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(name = "token", nullable = false, unique = true, length = 255)
    private String token;

    @Column(name = "user_email", nullable = false, length = 100)
    private String userEmail;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "expiry_date", nullable = false)
    private Instant expiryDate;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "verified", nullable = false)
    @Builder.Default
    private Boolean verified = false;

    @Column(name = "verified_at")
    private Instant verifiedAt;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    /**
     * Vérifie si le token est expiré
     */
    public boolean isExpired() {
        return Instant.now().isAfter(this.expiryDate);
    }

    /**
     * Vérifie si le token est valide (non expiré et non vérifié)
     */
    public boolean isValid() {
        return !isExpired() && !verified;
    }

    /**
     * Marque le token comme vérifié
     */
    public void markAsVerified() {
        this.verified = true;
        this.verifiedAt = Instant.now();
    }

    /**
     * Vérifie si le token peut être utilisé
     */
    public boolean canBeUsed() {
        return isValid();
    }
}