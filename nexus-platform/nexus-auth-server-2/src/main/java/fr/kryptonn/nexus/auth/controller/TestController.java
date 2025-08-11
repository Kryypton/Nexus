package fr.kryptonn.nexus.auth.controller;

import fr.kryptonn.nexus.common.dto.EmailImportance;
import fr.kryptonn.nexus.common.service.EmailNotificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/test")
@RequiredArgsConstructor
@Slf4j
public class TestController {

    private final EmailNotificationService emailNotificationService;


    @GetMapping("/email")
    public String previewEmailTestPage(Model model,
                                       @RequestParam(defaultValue = "INFO") String importance,
                                       @RequestParam(defaultValue = "Utilisateur Test") String userName,
                                       @RequestParam(defaultValue = "Aperçu Email Test") String title,
                                       @RequestParam(defaultValue = "Ceci est un aperçu de l'email de test. Vous pouvez voir à quoi ressemble l'email sans l'envoyer.") String content,
                                       @RequestParam(defaultValue = "false") boolean withButtons,
                                       @RequestParam(required = false) String customIcon) {

        try {
            // Mapper le type d'importance pour obtenir l'icône
            EmailImportance emailImportance = EmailImportance.valueOf(importance.toUpperCase());
            String iconName;

            if (emailImportance == EmailImportance.CUSTOM && customIcon != null) {
                iconName = customIcon;
            } else {
                iconName = emailImportance.getDefaultIcon();
            }

            // Préparer les données pour le template
            model.addAttribute("pageTitle", "Aperçu Email - " + title);
            model.addAttribute("userName", userName);
            model.addAttribute("iconName", iconName);
            model.addAttribute("notificationTitle", title);
            model.addAttribute("notificationContent", content);
            model.addAttribute("importance", emailImportance.name().toLowerCase());
            model.addAttribute("baseUrl", "http://localhost:9000");

            // Ajouter des boutons si demandé
            if (withButtons) {
                Map<String, String> buttons = Map.of(
                        "Dashboard", "http://localhost:4200/dashboard",
                        "Documentation", "http://localhost:9000/docs",
                        "Support", "mailto:support@nexus.fr"
                );
                model.addAttribute("buttons", buttons);
            }

            log.info("Aperçu email généré - Type: {}, Titre: {}", importance, title);

            // Retourner le template email pour affichage dans le navigateur
            return "email/layout/email-notification";

        } catch (IllegalArgumentException e) {
            // En cas d'erreur, utiliser des valeurs par défaut
            log.warn("Type d'importance invalide: {}, utilisation de INFO par défaut", importance);

            model.addAttribute("pageTitle", "Aperçu Email - " + title);
            model.addAttribute("userName", userName);
            model.addAttribute("iconName", "info");
            model.addAttribute("notificationTitle", title);
            model.addAttribute("notificationContent", content);
            model.addAttribute("importance", "info");
            model.addAttribute("baseUrl", "http://localhost:9000");

            return "email/layout/email-notification";
        }
    }

    @PostMapping("/email")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendTestEmail(
            @RequestParam String recipientEmail,
            @RequestParam(defaultValue = "Utilisateur Test") String recipientName,
            @RequestParam(defaultValue = "INFO") String importance,
            @RequestParam(defaultValue = "Email de Test") String title,
            @RequestParam(defaultValue = "Ceci est un email de test envoyé depuis l'endpoint de test Nexus.") String content,
            @RequestParam(required = false) String customIcon,
            @RequestParam(defaultValue = "false") boolean withButtons) {

        try {
            EmailImportance emailImportance = EmailImportance.valueOf(importance.toUpperCase());

            Map<String, Object> result = new HashMap<>();
            result.put("status", "success");
            result.put("recipientEmail", recipientEmail);
            result.put("recipientName", recipientName);
            result.put("importance", emailImportance.name());
            result.put("title", title);

            if (withButtons) {
                // Email avec boutons de test
                Map<String, String> buttons = Map.of(
                        "Dashboard", "http://localhost:4200/dashboard",
                        "Documentation", "http://localhost:9000/docs",
                        "Support", "mailto:support@nexus.fr"
                );

                emailNotificationService.sendNotificationWithButtons(
                        recipientEmail, recipientName, emailImportance, title, content, buttons
                );

                result.put("buttonsIncluded", true);
                result.put("buttons", buttons);
            } else if (emailImportance == EmailImportance.CUSTOM && customIcon != null) {
                // Email avec icône personnalisée
                emailNotificationService.sendCustomNotification(
                        recipientEmail, recipientName, customIcon, title, content
                );

                result.put("customIcon", customIcon);
            } else {
                // Email simple
                emailNotificationService.sendNotification(
                        recipientEmail, recipientName, emailImportance, title, content
                );
            }

            result.put("message", "Email envoyé avec succès");
            result.put("timestamp", System.currentTimeMillis());

            log.info("Email de test envoyé à {} avec le type {}", recipientEmail, emailImportance);

            return ResponseEntity.ok(result);

        } catch (IllegalArgumentException e) {
            log.warn("Type d'importance invalide: {}", importance);
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", "Type d'importance invalide. Utilisez: ALERT, WARN, INFO, SUCCESS, CUSTOM",
                    "allowedTypes", new String[]{"ALERT", "WARN", "INFO", "SUCCESS", "CUSTOM"}
            ));

        } catch (Exception e) {
            log.error("Erreur lors de l'envoi de l'email de test: {}", e.getMessage());
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Erreur lors de l'envoi: " + e.getMessage()
            ));
        }
    }
}