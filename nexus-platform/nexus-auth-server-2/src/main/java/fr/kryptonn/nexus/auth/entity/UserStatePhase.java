package fr.kryptonn.nexus.auth.entity;

public enum UserStatePhase {
    INITIAL,
    EMAIL_VERIFICATION,
    DISCORD_LINKING,
    BATTLE_NET_LINKING,
    COMPLETED
}
