package fr.kryptonn.nexus.common.service;

import fr.kryptonn.nexus.common.dto.EmailImportance;
import fr.kryptonn.nexus.common.dto.EmailNotificationDto;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.io.UnsupportedEncodingException;
import java.util.Map;

/**
 * Service d'envoi de notifications par email
 * Utilise les templates Thymeleaf compatibles avec les clients email
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailNotificationService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    /**
     * Envoie une notification email avec les paramètres spécifiés
     */
    public void sendNotification(
            String recipientEmail,
            String recipientName,
            EmailImportance importance,
            String title,
            String content) {

        sendNotification(recipientEmail, recipientName, importance, title, content, null, null);
    }

    /**
     * Envoie une notification email avec icône personnalisée
     */
    public void sendCustomNotification(
            String recipientEmail,
            String recipientName,
            String customIcon,
            String title,
            String content) {

        sendNotification(recipientEmail, recipientName, EmailImportance.CUSTOM, title, content, customIcon, null);
    }

    /**
     * Envoie une notification email avec boutons
     */
    public void sendNotificationWithButtons(
            String recipientEmail,
            String recipientName,
            EmailImportance importance,
            String title,
            String content,
            Map<String, String> buttons) {

        sendNotification(recipientEmail, recipientName, importance, title, content, null, buttons);
    }

    /**
     * Envoie une notification email complète avec tous les paramètres
     */
    public void sendNotification(
            String recipientEmail,
            String recipientName,
            EmailImportance importance,
            String title,
            String content,
            String customIcon,
            Map<String, String> buttons) {

        try {
            // Créer le DTO et valider
            EmailNotificationDto notification = EmailNotificationDto.builder()
                    .recipientEmail(recipientEmail)
                    .recipientName(recipientName)
                    .importance(importance)
                    .title(title)
                    .content(content)
                    .customIcon(customIcon)
                    .buttons(buttons)
                    .build();

            notification.validate();

            // Générer et envoyer l'email
            sendEmail(notification);

            log.info("Email de notification envoyé avec succès à {} (type: {})",
                    recipientEmail, importance.getDisplayName());

        } catch (Exception e) {
            log.error("Erreur lors de l'envoi de la notification email à {}: {}",
                    recipientEmail, e.getMessage());
            throw new RuntimeException("Impossible d'envoyer la notification email", e);
        }
    }

    /**
     * Méthodes de convenance pour chaque type d'importance
     */
    public void sendAlertEmail(String recipientEmail, String recipientName, String title, String content) {
        sendNotification(recipientEmail, recipientName, EmailImportance.ALERT, title, content);
    }

    public void sendWarningEmail(String recipientEmail, String recipientName, String title, String content) {
        sendNotification(recipientEmail, recipientName, EmailImportance.WARN, title, content);
    }

    public void sendInfoEmail(String recipientEmail, String recipientName, String title, String content) {
        sendNotification(recipientEmail, recipientName, EmailImportance.INFO, title, content);
    }

    public void sendSuccessEmail(String recipientEmail, String recipientName, String title, String content) {
        sendNotification(recipientEmail, recipientName, EmailImportance.SUCCESS, title, content);
    }

    /**
     * Avec boutons pour chaque type
     */
    public void sendAlertEmailWithButtons(String recipientEmail, String recipientName,
                                          String title, String content, Map<String, String> buttons) {
        sendNotificationWithButtons(recipientEmail, recipientName, EmailImportance.ALERT, title, content, buttons);
    }

    public void sendWarningEmailWithButtons(String recipientEmail, String recipientName,
                                            String title, String content, Map<String, String> buttons) {
        sendNotificationWithButtons(recipientEmail, recipientName, EmailImportance.WARN, title, content, buttons);
    }

    public void sendInfoEmailWithButtons(String recipientEmail, String recipientName,
                                         String title, String content, Map<String, String> buttons) {
        sendNotificationWithButtons(recipientEmail, recipientName, EmailImportance.INFO, title, content, buttons);
    }

    public void sendSuccessEmailWithButtons(String recipientEmail, String recipientName,
                                            String title, String content, Map<String, String> buttons) {
        sendNotificationWithButtons(recipientEmail, recipientName, EmailImportance.SUCCESS, title, content, buttons);
    }

    /**
     * Envoie l'email en utilisant le template Thymeleaf compatible email
     */
    private void sendEmail(EmailNotificationDto notification) throws MessagingException, UnsupportedEncodingException {

        // Préparer le contexte Thymeleaf
        Context context = new Context();
        context.setVariable("pageTitle", "Notification - " + notification.getTitle());
        context.setVariable("userName", notification.getRecipientName());
        context.setVariable("iconName", notification.getIcon());
        context.setVariable("notificationTitle", notification.getTitle());
        context.setVariable("notificationContent", notification.getContent());
        context.setVariable("importance", notification.getImportance().name().toLowerCase());
        context.setVariable("buttons", notification.getButtons());

        // Ajouter l'URL de base pour les assets
        context.setVariable("baseUrl", "http://localhost:9000"); // À configurer selon l'environnement

        // Générer le contenu HTML avec le template compatible email
        String htmlContent = templateEngine.process("email/layout/email-notification", context);

        // Créer et configurer le message
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setTo(notification.getRecipientEmail());
        helper.setSubject(getEmailSubject(notification));
        helper.setText(htmlContent, true);
        helper.setFrom("noreply@nexus.fr", "Nexus Platform");

        // Envoyer l'email
        mailSender.send(message);

        log.debug("Email HTML généré pour {} : template utilisé = email/layout/email-notification",
                notification.getRecipientEmail());
    }

    /**
     * Génère le sujet de l'email selon l'importance
     */
    private String getEmailSubject(EmailNotificationDto notification) {
        String prefix = switch (notification.getImportance()) {
            case ALERT -> "[🚨 ALERTE]";
            case WARN -> "[⚠️ ATTENTION]";
            case SUCCESS -> "[✅ SUCCÈS]";
            case INFO -> "[ℹ️ INFO]";
            case CUSTOM -> "[📧]";
        };

        return prefix + " " + notification.getTitle() + " - Nexus Platform";
    }

    /**
     * Méthode de test pour envoyer un email de démonstration
     */
    public void sendTestEmail(String recipientEmail, String recipientName) {
        Map<String, String> testButtons = Map.of(
                "Voir le Dashboard", "http://localhost:4200/dashboard",
                "Nous Contacter", "http://localhost:4200/contact"
        );

        sendNotificationWithButtons(
                recipientEmail,
                recipientName,
                EmailImportance.INFO,
                "Test de Notification",
                "Ceci est un email de test pour vérifier le bon fonctionnement du système de notifications Nexus.",
                testButtons
        );
    }
}