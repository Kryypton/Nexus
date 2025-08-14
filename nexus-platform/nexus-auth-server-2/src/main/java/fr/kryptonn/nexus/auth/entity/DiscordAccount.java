package fr.kryptonn.nexus.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Informations de base pour un compte Discord lié
 */
@Embeddable
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DiscordAccount {

    @Column(name = "discord_id")
    private String id;

    @Column(name = "discord_access_token")
    private String accessToken;

    @Column(name = "discord_refresh_token")
    private String refreshToken;

    @Column(name = "discord_token_expiry")
    private LocalDateTime tokenExpiry;
}
