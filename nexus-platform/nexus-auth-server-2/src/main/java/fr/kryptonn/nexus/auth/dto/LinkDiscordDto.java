package fr.kryptonn.nexus.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

/**
 * DTO utilisé pour lier un compte Discord à un utilisateur.
 */
@Data
@Builder
public class LinkDiscordDto {

    /** Identifiant Discord de l'utilisateur. */
    @NotBlank
    private String discordId;

    /** Token d'accès retourné par Discord. */
    @NotBlank
    private String accessToken;

    /** Refresh token Discord permettant de régénérer le token d'accès. */
    @NotBlank
    private String refreshToken;

    /** Durée de validité du token en secondes. */
    @NotNull
    private Long expiresIn;
}

