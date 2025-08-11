package fr.kryptonn.nexus.auth.dto;

import jakarta.validation.constraints.Email;
import lombok.Data;

/**
 * DTO de mise à jour utilisateur - Email uniquement
 */
@Data
public class UpdateUserDto {

    @Email(message = "L'email doit être valide")
    private String email;
}