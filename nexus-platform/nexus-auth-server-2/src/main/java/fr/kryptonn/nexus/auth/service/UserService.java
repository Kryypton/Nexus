package fr.kryptonn.nexus.auth.service;

import fr.kryptonn.nexus.auth.dto.ChangePasswordDto;
import fr.kryptonn.nexus.auth.dto.LinkBattleNetDto;
import fr.kryptonn.nexus.auth.dto.LinkDiscordDto;
import fr.kryptonn.nexus.auth.dto.UpdateUserDto;
import fr.kryptonn.nexus.auth.dto.UserResponseDto;
import fr.kryptonn.nexus.auth.entity.User;
import fr.kryptonn.nexus.auth.exception.AuthenticationException;
import fr.kryptonn.nexus.auth.exception.ResourceNotFoundException;
import fr.kryptonn.nexus.auth.exception.UserAlreadyExistsException;
import fr.kryptonn.nexus.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;
import java.time.LocalDateTime;

/**
 * Service utilisateur simplifié - Email comme seul identifiant
 * Plus de gestion du username séparé
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Trouve un utilisateur par email (identifiant principal)
     */
    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Utilisateur non trouvé avec l'email: " + email));
    }

    /**
     * Trouve un utilisateur par ID
     */
    @Transactional(readOnly = true)
    public User findById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Utilisateur non trouvé avec l'ID: " + id));
    }

    /**
     * Sauvegarde un utilisateur
     */
    public User save(User user) {
        return userRepository.save(user);
    }

    /**
     * Vérifie si un utilisateur existe par email
     */
    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    /**
     * Récupère tous les utilisateurs
     */
    @Transactional(readOnly = true)
    public List<UserResponseDto> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(UserResponseDto::fromUser)
                .collect(Collectors.toList());
    }

    /**
     * Récupère un utilisateur par ID sous forme de DTO
     */
    @Transactional(readOnly = true)
    public UserResponseDto getUserById(Long id) {
        User user = findById(id);
        return UserResponseDto.fromUser(user);
    }

    /**
     * Récupère un utilisateur par email sous forme de DTO
     */
    @Transactional(readOnly = true)
    public UserResponseDto getUserByEmail(String email) {
        User user = findByEmail(email);
        return UserResponseDto.fromUser(user);
    }

    /**
     * Met à jour un utilisateur
     */
    public UserResponseDto updateUser(Long id, UpdateUserDto updateDto) {
        User user = findById(id);

        // Mise à jour de l'email si fourni et différent
        if (updateDto.getEmail() != null && !updateDto.getEmail().equals(user.getEmail())) {
            if (existsByEmail(updateDto.getEmail())) {
                throw new UserAlreadyExistsException("L'email existe déjà: " + updateDto.getEmail());
            }
            user.setEmail(updateDto.getEmail());
            log.info("Email mis à jour pour l'utilisateur ID {}: {} -> {}",
                    id, user.getEmail(), updateDto.getEmail());
        }

        User savedUser = save(user);
        log.info("Utilisateur mis à jour: {}", savedUser.getEmail());

        return UserResponseDto.fromUser(savedUser);
    }

    /**
     * Supprime un utilisateur
     */
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new ResourceNotFoundException("Utilisateur non trouvé avec l'ID: " + id);
        }

        userRepository.deleteById(id);
        log.info("Utilisateur supprimé avec l'ID: {}", id);
    }

    /**
     * Change le mot de passe d'un utilisateur
     */
    public UserResponseDto changePassword(Long id, ChangePasswordDto changePasswordDto) {
        User user = findById(id);

        // Vérifier l'ancien mot de passe
        if (!passwordEncoder.matches(changePasswordDto.getCurrentPassword(), user.getPassword())) {
            throw new AuthenticationException("Le mot de passe actuel est incorrect");
        }

        // Vérifier la correspondance des nouveaux mots de passe
        if (!changePasswordDto.getNewPassword().equals(changePasswordDto.getConfirmNewPassword())) {
            throw new AuthenticationException("Les nouveaux mots de passe ne correspondent pas");
        }

        // Mettre à jour le mot de passe
        user.setPassword(passwordEncoder.encode(changePasswordDto.getNewPassword()));
        User savedUser = save(user);

        log.info("Mot de passe changé pour l'utilisateur: {}", savedUser.getEmail());
        return UserResponseDto.fromUser(savedUser);
    }

    /**
     * Active ou désactive un utilisateur
     */
    public UserResponseDto enableUser(Long id, boolean enabled) {
        User user = findById(id);
        user.setEnabled(enabled);

        User savedUser = save(user);
        log.info("Utilisateur {} {}: {}", enabled ? "activé" : "désactivé",
                savedUser.getEmail(), savedUser.getUserId());

        return UserResponseDto.fromUser(savedUser);
    }

    /**
     * Ajoute une autorité à un utilisateur
     */
    public UserResponseDto addAuthority(Long id, String authority) {
        User user = findById(id);

        if (!user.hasAuthority(authority)) {
            user.addAuthority(authority);
            User savedUser = save(user);
            log.info("Autorité '{}' ajoutée à l'utilisateur: {}", authority, savedUser.getEmail());
            return UserResponseDto.fromUser(savedUser);
        }

        log.debug("L'utilisateur {} a déjà l'autorité '{}'", user.getEmail(), authority);
        return UserResponseDto.fromUser(user);
    }

    /**
     * Supprime une autorité d'un utilisateur
     */
    public UserResponseDto removeAuthority(Long id, String authority) {
        User user = findById(id);
        user.removeAuthority(authority);

        User savedUser = save(user);
        log.info("Autorité '{}' supprimée de l'utilisateur: {}", authority, savedUser.getEmail());

        return UserResponseDto.fromUser(savedUser);
    }

    /**
     * Récupère les utilisateurs actifs uniquement
     */
    @Transactional(readOnly = true)
    public List<UserResponseDto> getActiveUsers() {
        return userRepository.findAllEnabledUsers()
                .stream()
                .map(UserResponseDto::fromUser)
                .collect(Collectors.toList());
    }

    /**
     * Compte le nombre total d'utilisateurs
     */
    @Transactional(readOnly = true)
    public long getTotalUserCount() {
        return userRepository.count();
    }

    /**
     * Compte le nombre d'utilisateurs actifs
     */
    @Transactional(readOnly = true)
    public long getActiveUserCount() {
        return userRepository.findAllEnabledUsers().size();
    }

    /**
     * Lie un compte Discord à l'utilisateur.
     */
    public UserResponseDto linkDiscordAccount(Long id, LinkDiscordDto dto) {
        User user = findById(id);

        user.setDiscordId(dto.getDiscordId());
        user.setDiscordAccessToken(dto.getAccessToken());
        user.setDiscordRefreshToken(dto.getRefreshToken());
        user.setDiscordTokenExpiry(LocalDateTime.now().plusSeconds(dto.getExpiresIn()));

        // Mise à jour de la phase d'état
        if (user.getStatePhase() == null || user.getStatePhase() == fr.kryptonn.nexus.auth.entity.UserStatePhase.DISCORD_LINKING || user.getStatePhase() == fr.kryptonn.nexus.auth.entity.UserStatePhase.EMAIL_VERIFICATION || user.getStatePhase() == fr.kryptonn.nexus.auth.entity.UserStatePhase.INITIAL) {
            user.setStatePhase(fr.kryptonn.nexus.auth.entity.UserStatePhase.BATTLE_NET_LINKING);
        }

        User saved = save(user);
        return UserResponseDto.fromUser(saved);
    }

    /**
     * Lie un compte Battle.net à l'utilisateur.
     */
    public UserResponseDto linkBattleNetAccount(Long id, LinkBattleNetDto dto) {
        User user = findById(id);

        user.setBattleNetId(dto.getBattleNetId());
        user.setBattleNetAccessToken(dto.getAccessToken());
        user.setBattleNetTokenExpiry(LocalDateTime.now().plusSeconds(dto.getExpiresIn()));

        // Si le compte Discord est déjà lié, l'utilisateur est complet
        if (user.getDiscordId() != null) {
            user.setStatePhase(fr.kryptonn.nexus.auth.entity.UserStatePhase.COMPLETED);
        } else {
            user.setStatePhase(fr.kryptonn.nexus.auth.entity.UserStatePhase.DISCORD_LINKING);
        }

        User saved = save(user);
        return UserResponseDto.fromUser(saved);
    }
}