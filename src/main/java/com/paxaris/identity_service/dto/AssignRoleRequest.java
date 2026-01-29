package com.paxaris.identity_service.dto;

import lombok.Data;

@Data
public class AssignRoleRequest {
    private String name; // client role name in Keycloak
}
