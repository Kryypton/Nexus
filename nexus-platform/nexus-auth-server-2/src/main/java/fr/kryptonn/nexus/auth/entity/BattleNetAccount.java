package fr.kryptonn.nexus.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Informations de base pour un compte Battle.net lié
 */
@Embeddable
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BattleNetAccount {

    @Column(name = "battlenet_id")
    private String id;

    @Column(name = "battlenet_access_token")
    private String accessToken;

    @Column(name = "battlenet_token_expiry")
    private LocalDateTime tokenExpiry;
}
