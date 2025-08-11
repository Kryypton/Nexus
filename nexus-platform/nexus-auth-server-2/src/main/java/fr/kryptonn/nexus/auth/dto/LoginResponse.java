package fr.kryptonn.nexus.auth.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class LoginResponse {
    private String token;
    private String refreshToken;
    private long expiresIn;
    private String tokenType;
    private UserResponseDto user;
}

