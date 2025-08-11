package fr.kryptonn.nexus.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class OAuth2ClientConfig {

    @Value("${NEXUS_WEB_CLIENT_SECRET}")
    private String webClientSecret;

    @Value("${NEXUS_SYNAPSE_CLIENT_SECRET}")
    private String synapseClientSecret;

    @Value("${NEXUS_WEB_REDIRECT_URI}")
    private String webRedirectUri;

    @Value("${NEXUS_AUTH_ISSUER_URI}")
    private String issuerUri;

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Client pour l'application web Nexus
        RegisteredClient nexusWebApp = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("nexus-web-app")
                .clientSecret("{noop}" + webClientSecret) // {noop} pour développement, utiliser {bcrypt} en prod
                .clientName("Nexus Web Application")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(webRedirectUri)
                .redirectUri("http://localhost:4200/login/oauth2/code/nexus") // URL de dev additionnelle
                .postLogoutRedirectUri("http://localhost:4200/logout")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .scope("write")
                .scope("admin")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false) // Pas besoin de consentement pour notre propre app
                        .requireProofKey(true) // PKCE pour sécurité additionnelle
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        // Client pour le bot Discord Synapse
        RegisteredClient nexusSynapseBot = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("nexus-synapse-bot")
                .clientSecret("{noop}" + synapseClientSecret) // {noop} pour développement
                .clientName("Nexus Synapse Discord Bot")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("bot:read")
                .scope("bot:write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(2))
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(nexusWebApp, nexusSynapseBot);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuerUri)
                .authorizationEndpoint("/oauth2/authorize")
                .deviceAuthorizationEndpoint("/oauth2/device_authorization")
                .deviceVerificationEndpoint("/oauth2/device_verification")
                .tokenEndpoint("/oauth2/token")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .jwkSetEndpoint("/oauth2/jwks")
                .oidcLogoutEndpoint("/connect/logout")
                .oidcUserInfoEndpoint("/userinfo")
                .oidcClientRegistrationEndpoint("/connect/register")
                .build();
    }
}