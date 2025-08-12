package fr.kryptonn.nexus.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

/**
 * DTO utilisé pour lier un compte Battle.net à un utilisateur.
 */
@Data
@Builder
public class LinkBattleNetDto {

    /** Identifiant Battle.net de l'utilisateur. */
    @NotBlank
    private String battleNetId;

    /** Token d'accès retourné par Battle.net. */
    @NotBlank
    private String accessToken;

    /** Durée de validité du token en secondes. */
    @NotNull
    private Long expiresIn;
}

