package fr.kryptonn.nexus.auth.dto;

import lombok.Data;

@Data
public class ChangePasswordDto {
    private String currentPassword;
    private String newPassword;
    private String confirmNewPassword;
}
