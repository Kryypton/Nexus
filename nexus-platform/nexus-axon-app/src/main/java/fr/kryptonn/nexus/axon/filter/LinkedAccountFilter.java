package fr.kryptonn.nexus.axon.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtre vérifiant que l'utilisateur a bien lié ses comptes Discord et Battle.net
 * avant d'accéder aux endpoints protégés de l'application Axon.
 */
@Component
public class LinkedAccountFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwtAuth && authentication.isAuthenticated()) {
            Boolean discordLinked = jwtAuth.getToken().getClaim("discordLinked");
            Boolean battleNetLinked = jwtAuth.getToken().getClaim("battleNetLinked");

            if (Boolean.FALSE.equals(discordLinked) || Boolean.FALSE.equals(battleNetLinked)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"LINK_REQUIRED\",\"message\":\"Discord et Battle.net doivent être liés\"}");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}

