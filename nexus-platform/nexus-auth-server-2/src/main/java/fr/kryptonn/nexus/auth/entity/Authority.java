package fr.kryptonn.nexus.auth.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.Objects;

/**
 * Entité Authority mise à jour pour compatibilité avec User simplifié
 */
@Entity
@Table(name = "authorities", indexes = {
        @Index(name = "idx_authority_name", columnList = "authority"),
        @Index(name = "idx_authority_user", columnList = "user_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Authority implements GrantedAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false, length = 50)
    private String authority;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonIgnore
    private User user;

    @Override
    public String getAuthority() {
        return authority;
    }

    // Optimisation des comparaisons pour les collections
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Authority authority1 = (Authority) o;
        return Objects.equals(authority, authority1.authority) &&
                Objects.equals(user != null ? user.getUserId() : null,
                        authority1.user != null ? authority1.user.getUserId() : null);
    }

    @Override
    public int hashCode() {
        return Objects.hash(authority, user != null ? user.getUserId() : null);
    }

    @Override
    public String toString() {
        return "Authority{" +
                "id='" + id + '\'' +
                ", authority='" + authority + '\'' +
                ", userId='" + (user != null ? user.getUserId() : "null") + '\'' +
                '}';
    }
}