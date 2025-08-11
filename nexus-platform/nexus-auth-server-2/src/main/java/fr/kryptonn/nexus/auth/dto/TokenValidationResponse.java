package fr.kryptonn.nexus.auth.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenValidationResponse {
    private boolean valid;
    private String username;
    private boolean expired;
    private String message;
}
