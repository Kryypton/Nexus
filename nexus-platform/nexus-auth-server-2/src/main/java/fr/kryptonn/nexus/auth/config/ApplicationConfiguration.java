package fr.kryptonn.nexus.auth.config;

import fr.kryptonn.nexus.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configuration d'application simplifiée - Email comme identifiant unique
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class ApplicationConfiguration {

    private final UserRepository userRepository;

    /**
     * UserDetailsService utilisant l'email comme identifiant
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return email -> {
            log.debug("Chargement des détails utilisateur pour l'email: {}", email);

            return userRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        log.warn("Utilisateur non trouvé avec l'email: {}", email);
                        return new UsernameNotFoundException("Utilisateur non trouvé: " + email);
                    });
        };
    }

    /**
     * Encodeur de mot de passe avec BCrypt sécurisé
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // Force 12 pour sécurité renforcée
    }

    /**
     * Gestionnaire d'authentification
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Provider d'authentification personnalisé
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        authProvider.setHideUserNotFoundExceptions(false); // Pour debugging
        return authProvider;
    }
}