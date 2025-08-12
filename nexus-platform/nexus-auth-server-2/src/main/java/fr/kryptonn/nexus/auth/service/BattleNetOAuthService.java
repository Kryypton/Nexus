package fr.kryptonn.nexus.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/**
 * Service utilitaire pour les échanges OAuth2 avec Battle.net.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BattleNetOAuthService {

    @Value("${battlenet.client-id:}")
    private String clientId;

    @Value("${battlenet.client-secret:}")
    private String clientSecret;

    @Value("${battlenet.token-uri:https://oauth.battle.net/token}")
    private String tokenUri;

    @Value("${battlenet.user-info-uri:https://oauth.battle.net/oauth/userinfo}")
    private String userInfoUri;

    private final RestTemplate restTemplate;

    /**
     * Échange un code d'autorisation contre un token Battle.net.
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
     * Récupère l'identifiant Battle.net de l'utilisateur depuis le token d'accès.
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
            if (id instanceof Number n) {
                return String.valueOf(n.longValue());
            }
        }
        return null;
    }
}
