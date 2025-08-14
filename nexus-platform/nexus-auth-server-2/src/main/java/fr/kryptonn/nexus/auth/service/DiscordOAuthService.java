package fr.kryptonn.nexus.auth.service;

import fr.kryptonn.nexus.auth.entity.User;
import fr.kryptonn.nexus.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Service gérant la régénération automatique des tokens Discord à partir du refresh token.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DiscordOAuthService {

    @Value("${discord.client-id:}")
    private String clientId;

    @Value("${discord.client-secret:}")
    private String clientSecret;

    @Value("${discord.token-uri:https://discord.com/api/oauth2/token}")
    private String tokenUri;

    @Value("${discord.user-info-uri:https://discord.com/api/users/@me}")
    private String userInfoUri;

    private final UserRepository userRepository;
    private final RestTemplate restTemplate;

    /**
     * Échange un code d'autorisation contre des tokens Discord.
     */
    public Map<String, Object> exchangeCode(String code, String redirectUri) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("grant_type", "authorization_code");
        body.add("code", code);
        body.add("redirect_uri", redirectUri);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        return restTemplate.postForObject(tokenUri, new HttpEntity<>(body, headers), Map.class);
    }

    /**
     * Récupère l'identifiant de l'utilisateur Discord à partir du token d'accès.
     */
    public String fetchUserId(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        Map<String, Object> response = restTemplate.exchange(
                userInfoUri,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                Map.class
        ).getBody();
        if (response != null) {
            Object id = response.get("id");
            if (id instanceof String s) {
                return s;
            }
        }
        return null;
    }

    /**
     * Vérifie régulièrement les tokens Discord et les régénère si nécessaire.
     */
    @Scheduled(fixedDelay = 300000) // Toutes les 5 minutes
    public void refreshDiscordTokens() {
        List<User> users = userRepository.findByDiscordAccount_RefreshTokenIsNotNull();
        LocalDateTime now = LocalDateTime.now();

        for (User user : users) {
            if (user.getDiscordTokenExpiry() != null &&
                    user.getDiscordTokenExpiry().isBefore(now.plusMinutes(5))) {
                try {
                    refreshToken(user);
                } catch (Exception e) {
                    log.warn("Erreur lors du rafraîchissement du token Discord pour {}: {}", user.getEmail(), e.getMessage());
                }
            }
        }
    }

    /**
     * Rafraîchit le token Discord d'un utilisateur.
     */
    public void refreshToken(User user) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("grant_type", "refresh_token");
        body.add("refresh_token", user.getDiscordRefreshToken());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        Map<String, Object> response = restTemplate.postForObject(
                tokenUri,
                new HttpEntity<>(body, headers),
                Map.class);

        if (response != null) {
            user.setDiscordAccessToken((String) response.get("access_token"));
            Object refresh = response.get("refresh_token");
            if (refresh instanceof String refreshStr) {
                user.setDiscordRefreshToken(refreshStr);
            }
            Object expires = response.get("expires_in");
            if (expires instanceof Number exp) {
                user.setDiscordTokenExpiry(LocalDateTime.now().plusSeconds(exp.longValue()));
            }
            userRepository.save(user);
            log.debug("Token Discord rafraîchi pour {}", user.getEmail());
        }
    }
}

