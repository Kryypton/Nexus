package fr.kryptonn.nexus.auth.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Entité User simplifiée - L'email est désormais l'unique identifiant
 * Plus de confusion entre username et email
 */
@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = "email")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "email", unique = true, nullable = false, length = 100)
    @Email(message = "Format d'email invalide")
    private String email;

    @Column(nullable = false, length = 255)
    @JsonIgnore
    private String password;

    @OneToMany(mappedBy = "user", fetch = FetchType.EAGER, cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<Authority> authorities = new HashSet<>();

    @CreationTimestamp
    @Column(updatable = false, name = "created_at")
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(nullable = false)
    private UserStatePhase statePhase = UserStatePhase.INITIAL;

    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    @Column(nullable = false, name = "account_non_expired")
    @Builder.Default
    private Boolean accountNonExpired = true;

    @Column(nullable = false, name = "account_non_locked")
    @Builder.Default
    private Boolean accountNonLocked = true;

    @Column(nullable = false, name = "credentials_non_expired")
    @Builder.Default
    private Boolean credentialsNonExpired = true;

    @Column(name = "tokens_revoked_at")
    private LocalDateTime tokensRevokedAt;

    @Column(name = "discord_id")
    private String discordId;

    @Column(name = "discord_access_token")
    private String discordAccessToken;

    @Column(name = "discord_refresh_token")
    private String discordRefreshToken;

    @Column(name = "discord_token_expiry")
    private LocalDateTime discordTokenExpiry;

    @Column(name = "battlenet_id")
    private String battleNetId;

    @Column(name = "battlenet_access_token")
    private String battleNetAccessToken;

    @Column(name = "battlenet_token_expiry")
    private LocalDateTime battleNetTokenExpiry;

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public void addAuthority(String authority) {
        Authority auth = Authority.builder()
                .authority(authority)
                .user(this)
                .build();
        this.authorities.add(auth);
    }

    public void removeAuthority(String authority) {
        authorities.removeIf(auth -> auth.getAuthority().equals(authority));
    }

    public boolean hasAuthority(String authority) {
        return authorities.stream()
                .anyMatch(auth -> auth.getAuthority().equals(authority));
    }

    public String getEmail() {
        return email;
    }
}