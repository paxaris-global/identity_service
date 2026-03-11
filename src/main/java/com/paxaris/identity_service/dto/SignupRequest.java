package com.paxaris.identity_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(
        name = "SignupRequest",
        description = "Request payload for user signup and realm creation"
)
public class SignupRequest {

    @Schema(
            description = "Name of the Keycloak realm to create",
            example = "my-realm",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String realmName;

    @Schema(
            description = "Password for the admin user",
            example = "StrongPassword!ChangeMe",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String adminPassword;

    @Schema(
            description = "Admin username (optional). If omitted, service configuration is used",
            example = "admin"
    )
    private String adminUsername;
}
