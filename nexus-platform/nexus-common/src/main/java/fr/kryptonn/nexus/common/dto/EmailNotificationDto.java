package fr.kryptonn.nexus.common.dto;

import jakarta.validation.constraints.*;
import lombok.Builder;
import lombok.Data;

import java.util.Map;

/**
 * DTO pour les notifications par email
 */
@Data
@Builder
public class EmailNotificationDto {

    @NotBlank(message = "L'email du destinataire est requis")
    @Email(message = "L'email du destinataire doit être valide")
    private String recipientEmail;

    private String recipientName;

    @NotNull(message = "L'importance est requise")
    private EmailImportance importance;

    @Size(max = 32, message = "Le titre ne peut pas dépasser 32 caractères")
    private String title;

    @Size(max = 320, message = "Le contenu ne peut pas dépasser 320 caractères")
    private String content;

    private String customIcon;

    private Map<String, String> buttons;

    @AssertTrue(message = "Une icône personnalisée est requise pour le type CUSTOM")
    public boolean isCustomIconValid() {
        return importance != EmailImportance.CUSTOM ||
                (customIcon != null && !customIcon.trim().isEmpty());
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