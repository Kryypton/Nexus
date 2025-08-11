package fr.kryptonn.nexus.auth.config;

import fr.kryptonn.nexus.auth.service.JwtService;
import fr.kryptonn.nexus.auth.service.TokenBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

/**
 * Filtre JWT refactorisé avec vérification de blacklist
 * Utilise les nouveaux services séparés
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // Vérifier la présence du header Authorization
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String jwt = authHeader.substring(7);

            // Vérification basique du token (signature, expiration, format)
            if (!jwtService.validateToken(jwt)) {
                log.debug("Token JWT invalide ou expiré");
                filterChain.doFilter(request, response);
                return;
            }

            // Vérifier si le token est blacklisté
            if (tokenBlacklistService.isTokenBlacklisted(jwt)) {
                log.debug("Token JWT blacklisté détecté");
                filterChain.doFilter(request, response);
                return;
            }

            // Extraire l'email du token
            final String userEmail = jwtService.extractEmail(jwt);

            // Vérifier si l'utilisateur n'est pas déjà authentifié
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (userEmail != null && authentication == null) {

                // Charger les détails de l'utilisateur
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                // Validation finale avec les détails utilisateur
                if (jwtService.isTokenValid(jwt, userDetails)) {

                    // Créer le token d'authentification Spring Security
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    // Ajouter les détails de la requête
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Définir l'authentification dans le contexte
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.debug("Utilisateur authentifié via JWT: {}", userEmail);
                } else {
                    log.debug("Token JWT invalide pour l'utilisateur: {}", userEmail);
                }
            }
        } catch (Exception exception) {
            log.error("Erreur lors de l'authentification JWT: {}", exception.getMessage());

            // Utiliser le resolver d'exception pour une gestion propre
            handlerExceptionResolver.resolveException(request, response, null, exception);
            return;
        }

        filterChain.doFilter(request, response);
    }
}
