package fr.kryptonn.nexus.common.dto;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

/**
 * DTO pour les notifications par email
 */
@Data
@Builder
public class EmailNotificationDto {

    private String recipientEmail;
    private String recipientName;
    private EmailImportance importance;
    private String title;
    private String content;
    private String customIcon;
    private Map<String, String> buttons;

    /**
     * Valide les contraintes de taille
     */
    public void validate() {
        if (title != null && title.length() > 32) {
            throw new IllegalArgumentException("Le titre ne peut pas dépasser 32 caractères");
        }

        if (content != null && content.length() > 320) {
            throw new IllegalArgumentException("Le contenu ne peut pas dépasser 320 caractères");
        }

        if (importance == EmailImportance.CUSTOM && (customIcon == null || customIcon.trim().isEmpty())) {
            throw new IllegalArgumentException("Une icône personnalisée est requise pour le type CUSTOM");
        }

        if (recipientEmail == null || recipientEmail.trim().isEmpty()) {
            throw new IllegalArgumentException("L'email du destinataire est requis");
        }
    }

    /**
     * Retourne l'icône à utiliser selon le type d'importance
     */
    public String getIcon() {
        if (importance == EmailImportance.CUSTOM) {
            return customIcon;
        }
        return importance.getDefaultIcon();
    }
}