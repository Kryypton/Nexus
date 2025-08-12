package fr.kryptonn.nexus.auth.dto;

import fr.kryptonn.nexus.auth.entity.Authority;
import fr.kryptonn.nexus.auth.entity.User;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * DTO de réponse utilisateur simplifié
 */
@Data
@Builder
public class UserResponseDto {
    private Long userId;
    private String email; // Email comme identifiant unique
    private LocalDateTime createdAt;
    private Set<String> authorities;
    private Boolean enabled;
    private boolean discordLinked;
    private boolean battleNetLinked;

    public static UserResponseDto fromUser(User user) {
        return UserResponseDto.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .createdAt(user.getCreatedAt())
                .enabled(user.getEnabled())
                .discordLinked(user.getDiscordId() != null)
                .battleNetLinked(user.getBattleNetId() != null)
                .authorities(user.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet()))
                .build();
    }
}