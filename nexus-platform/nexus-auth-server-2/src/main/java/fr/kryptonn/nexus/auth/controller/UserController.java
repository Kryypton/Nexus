package fr.kryptonn.nexus.auth.controller;

import fr.kryptonn.nexus.auth.dto.ChangePasswordDto;
import fr.kryptonn.nexus.auth.dto.LinkBattleNetDto;
import fr.kryptonn.nexus.auth.dto.LinkDiscordDto;
import fr.kryptonn.nexus.auth.dto.UpdateUserDto;
import fr.kryptonn.nexus.auth.dto.UserResponseDto;
import fr.kryptonn.nexus.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@Validated
@Slf4j
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponseDto>> getAllUsers() {
        log.info("Récupération de tous les utilisateurs");
        List<UserResponseDto> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or authentication.principal.userId == #id")
    public ResponseEntity<UserResponseDto> getUserById(@PathVariable Long id) {
        log.info("Récupération de l'utilisateur avec l'ID: {}", id);
        UserResponseDto user = userService.getUserById(id);
        return ResponseEntity.ok(user);
    }

    @GetMapping("/by-email/{email}")
    @PreAuthorize("hasRole('ADMIN') or authentication.principal.email == #email")
    public ResponseEntity<UserResponseDto> getUserByEmail(@PathVariable String email) {
        log.info("Récupération de l'utilisateur avec l'email: {}", email);
        UserResponseDto user = userService.getUserByEmail(email);
        return ResponseEntity.ok(user);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or authentication.principal.userId == #id")
    public ResponseEntity<UserResponseDto> updateUser(
            @PathVariable Long id,
            @Valid @RequestBody UpdateUserDto updateDto) {
        log.info("Mise à jour de l'utilisateur avec l'ID: {}", id);
        UserResponseDto updatedUser = userService.updateUser(id, updateDto);
        return ResponseEntity.ok(updatedUser);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        log.info("Suppression de l'utilisateur avec l'ID: {}", id);
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/password")
    @PreAuthorize("hasRole('ADMIN') or authentication.principal.userId == #id")
    public ResponseEntity<UserResponseDto> changePassword(
            @PathVariable Long id,
            @Valid @RequestBody ChangePasswordDto changePasswordDto) {
        log.info("Changement de mot de passe pour l'utilisateur avec l'ID: {}", id);
        UserResponseDto updatedUser = userService.changePassword(id, changePasswordDto);
        return ResponseEntity.ok(updatedUser);
    }

    @PatchMapping("/{id}/enabled")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserResponseDto> enableUser(
            @PathVariable Long id,
            @RequestParam boolean enabled) {
        log.info("{} de l'utilisateur avec l'ID: {}", enabled ? "Activation" : "Désactivation", id);
        UserResponseDto updatedUser = userService.enableUser(id, enabled);
        return ResponseEntity.ok(updatedUser);
    }

    @PostMapping("/{id}/link/discord")
    @PreAuthorize("hasRole('ADMIN') or authentication.principal.userId == #id")
    public ResponseEntity<UserResponseDto> linkDiscord(
            @PathVariable Long id,
            @Valid @RequestBody LinkDiscordDto dto) {
        log.info("Lien du compte Discord pour l'utilisateur {}", id);
        return ResponseEntity.ok(userService.linkDiscordAccount(id, dto));
    }

    @PostMapping("/{id}/link/battlenet")
    @PreAuthorize("hasRole('ADMIN') or authentication.principal.userId == #id")
    public ResponseEntity<UserResponseDto> linkBattleNet(
            @PathVariable Long id,
            @Valid @RequestBody LinkBattleNetDto dto) {
        log.info("Lien du compte Battle.net pour l'utilisateur {}", id);
        return ResponseEntity.ok(userService.linkBattleNetAccount(id, dto));
    }
}