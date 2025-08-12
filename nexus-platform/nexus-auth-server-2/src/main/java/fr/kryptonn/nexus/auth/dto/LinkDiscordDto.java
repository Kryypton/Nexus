package fr.kryptonn.nexus.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

/**
 * DTO utilisé pour lier un compte Discord à un utilisateur.
 */
@Data
@Builder
public class LinkDiscordDto {

    /** Code d'autorisation retourné par Discord après l'OAuth2. */
    @NotBlank
    private String code;

    /** URI de redirection utilisée lors de l'authentification. */
    @NotBlank
    private String redirectUri;
}

