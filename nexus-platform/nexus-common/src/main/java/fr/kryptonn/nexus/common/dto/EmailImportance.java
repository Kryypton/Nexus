package fr.kryptonn.nexus.common.dto;

/**
 * Énumération des degrés d'importance pour les emails
 */
public enum EmailImportance {
    ALERT("bolt", "Alerte"),
    WARN("priority_high", "Avertissement"),
    INFO("info", "Information"),
    SUCCESS("check", "Succès"),
    CUSTOM("", "Personnalisé");

    private final String defaultIcon;
    private final String displayName;

    EmailImportance(String defaultIcon, String displayName) {
        this.defaultIcon = defaultIcon;
        this.displayName = displayName;
    }

    public String getDefaultIcon() {
        return defaultIcon;
    }

    public String getDisplayName() {
        return displayName;
    }
}