package fr.kryptonn.nexus.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class TokenValidationRequest {
    @NotBlank(message = "Le token est requis")
    private String token;
}