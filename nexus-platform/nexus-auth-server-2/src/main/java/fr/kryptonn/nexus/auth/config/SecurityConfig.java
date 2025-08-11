package fr.kryptonn.nexus.auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Configuration Spring Security moderne sans WebSecurityConfigurerAdapter
 * CORS géré par CorsConfig centralisé
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CorsConfigurationSource corsConfigurationSource; // Injection du bean centralisé

    /**
     * Configuration du filtre de sécurité principal
     */
    @Bean
    @Order(2) // Ordre 2 pour être après OAuth2 Authorization Server
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // Désactiver CSRF pour les APIs REST
                .csrf(AbstractHttpConfigurer::disable)

                // Configuration CORS avec source centralisée
                .cors(cors -> cors.configurationSource(corsConfigurationSource))

                // Gestion des sessions - stateless pour JWT
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configuration des autorisations
                .authorizeHttpRequests(auth -> auth
                        // Endpoints publics
                        .requestMatchers("/auth/signup", "/auth/login", "/auth/health","/auth/refresh").permitAll()
                        .requestMatchers("/public/**", "/error", "/actuator/health").permitAll()
                        .requestMatchers("/.well-known/**", "/oauth2/jwks").permitAll()
                        .requestMatchers("/test/**").permitAll() //TODO: remove
                        .requestMatchers("/images/**", "/css/**", "/js/**", "/static/**").permitAll()

                        // Endpoints d'authentification
                        .requestMatchers("/auth/me/**", "/auth/logout/**").authenticated()
                        .requestMatchers("/auth/validate-token").authenticated()
                        .requestMatchers("/auth/stats").hasRole("ADMIN")

                        // APIs utilisateurs
                        .requestMatchers(HttpMethod.GET, "/api/users/me").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/users/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/users/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/users/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/users/**").hasRole("ADMIN")
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // Tout le reste nécessite une authentification
                        .anyRequest().authenticated()
                )

                // Provider d'authentification personnalisé
                .authenticationProvider(authenticationProvider)

                // Ajouter le filtre JWT avant le filtre d'authentification standard
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

                .build();
    }
}