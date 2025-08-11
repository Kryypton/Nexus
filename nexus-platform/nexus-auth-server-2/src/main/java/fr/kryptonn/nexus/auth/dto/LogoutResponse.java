package fr.kryptonn.nexus.auth.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class LogoutResponse {
    private String message;
    private LocalDateTime timestamp;
}
