package com.paxaris.identity_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(
        name = "AssignRoleRequest",
        description = "Request payload for assigning roles to a user"
)
public class AssignRoleRequest {
    @Schema(
            description = "Name of the product role to assign",
            example = "admin",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String name;
}
