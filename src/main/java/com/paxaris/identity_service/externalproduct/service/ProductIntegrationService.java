package com.paxaris.identity_service.externalproduct.service;

import com.paxaris.identity_service.dto.AssignRoleRequest;

import java.util.List;
import java.util.Map;

/**
 * App-to-app operations for uploaded products (create user, assign roles).
 * Uses each product's client_id and client secret; does not require Paxo dashboard admin token.
 */
public interface ProductIntegrationService {

    String createProductUser(String realm, String productId, Map<String, Object> userPayload);

    void assignProductUserRoles(
            String realm,
            String productId,
            String username,
            List<AssignRoleRequest> roles);
}
