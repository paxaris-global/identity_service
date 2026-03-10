package com.paxaris.identity_service.dto;

 import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(
        name = "RoleCreationRequest",
        description = "Request payload for creating or updating product roles"
)
public class RoleCreationRequest {
    @Schema(
            description = "Name of the role",
            example = "admin",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String name;

    @Schema(
            description = "Description of the role",
            example = "Administrator role for product management",
            requiredMode = Schema.RequiredMode.NOT_REQUIRED
    )
    private String description;

    @Schema(
            description = "API endpoint URI associated with this role",
            example = "/api/products",
            requiredMode = Schema.RequiredMode.NOT_REQUIRED
    )
    private String uri;

    @Schema(
            description = "HTTP method associated with this role",
            example = "GET",
            allowableValues = {"GET", "POST", "PUT", "DELETE", "PATCH"},
            requiredMode = Schema.RequiredMode.NOT_REQUIRED
    )
    private String httpMethod;
}