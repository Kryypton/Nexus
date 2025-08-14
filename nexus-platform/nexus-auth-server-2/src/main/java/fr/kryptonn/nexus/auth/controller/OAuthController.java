package fr.kryptonn.nexus.auth.controller;

import fr.kryptonn.nexus.auth.dto.LinkBattleNetDto;
import fr.kryptonn.nexus.auth.dto.LinkDiscordDto;
import fr.kryptonn.nexus.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Endpoints de rappel OAuth2 pour l'association des comptes externes.
 */
@RestController
@RequestMapping("/api/oauth")
@RequiredArgsConstructor
@Slf4j
public class OAuthController {

    private final UserService userService;

    /**
     * Callback OAuth2 pour Battle.net. Le paramètre state doit contenir l'identifiant utilisateur.
     */
    @GetMapping("/battlenet/callback")
    public ResponseEntity<String> battleNetCallback(
            @RequestParam("code") String code,
            @RequestParam("state") String state,
            HttpServletRequest request) {
        log.debug("Réception du callback Battle.net pour l'utilisateur {}", state);
        Long userId = Long.valueOf(state);
        String redirectUri = ServletUriComponentsBuilder.fromRequestUri(request).build().toUriString();
        userService.linkBattleNetAccount(userId, LinkBattleNetDto.builder()
                .code(code)
                .redirectUri(redirectUri)
                .build());
        return ResponseEntity.ok("Battle.net account linked");
    }

    /**
     * Callback OAuth2 pour Discord. Le paramètre state doit contenir l'identifiant utilisateur.
     */
    @GetMapping("/discord/callback")
    public ResponseEntity<String> discordCallback(
            @RequestParam("code") String code,
            @RequestParam("state") String state,
            HttpServletRequest request) {
        log.debug("Réception du callback Discord pour l'utilisateur {}", state);
        Long userId = Long.valueOf(state);
        String redirectUri = ServletUriComponentsBuilder.fromRequestUri(request).build().toUriString();
        userService.linkDiscordAccount(userId, LinkDiscordDto.builder()
                .code(code)
                .redirectUri(redirectUri)
                .build());
        return ResponseEntity.ok("Discord account linked");
    }
}

