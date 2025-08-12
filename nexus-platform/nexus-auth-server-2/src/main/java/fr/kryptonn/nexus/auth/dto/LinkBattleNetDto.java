package fr.kryptonn.nexus.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

/**
 * DTO utilisé pour lier un compte Battle.net à un utilisateur.
 */
@Data
@Builder
public class LinkBattleNetDto {

    /** Code d'autorisation retourné par Battle.net après l'OAuth2. */
    @NotBlank
    private String code;

    /** URI de redirection utilisée lors de l'authentification. */
    @NotBlank
    private String redirectUri;
}

