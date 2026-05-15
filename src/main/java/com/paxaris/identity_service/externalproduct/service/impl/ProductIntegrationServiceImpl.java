package com.paxaris.identity_service.externalproduct.service.impl;

import com.paxaris.identity_service.dto.AssignRoleRequest;
import com.paxaris.identity_service.externalproduct.client.ProductIntegrationKeycloakClient;
import com.paxaris.identity_service.externalproduct.service.ProductIntegrationService;
import com.paxaris.identity_service.service.KeycloakProductService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Orchestrates external product app-to-app flows: resolve product secret, obtain Keycloak token,
 * then delegate user/role operations to {@link KeycloakProductService}.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ProductIntegrationServiceImpl implements ProductIntegrationService {

    private final KeycloakProductService keycloakProductService;
    private final ProductIntegrationKeycloakClient keycloakClient;

    @Override
    public String createProductUser(String realm, String productId, Map<String, Object> userPayload) {
        validateRealmAndProduct(realm, productId);
        String username = requireUsername(userPayload);

        String serviceToken = obtainProductServiceToken(realm, productId);

        if (keycloakClient.usernameExists(realm, username, serviceToken)) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Username already exists: " + username);
        }

        try {
            String userId = keycloakProductService.createUser(realm, serviceToken, userPayload);
            log.info("External product API created user '{}' (id={}) for product '{}' in realm '{}'",
                    username, userId, productId, realm);
            return userId;
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            log.error("External product API failed to create user '{}' for product '{}': {}",
                    username, productId, e.getMessage());
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Failed to create user: " + e.getMessage(),
                    e);
        }
    }

    @Override
    public void assignProductUserRoles(
            String realm,
            String productId,
            String username,
            List<AssignRoleRequest> roles) {
        validateRealmAndProduct(realm, productId);
        if (username == null || username.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "username is required");
        }
        if (roles == null || roles.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one role is required");
        }

        String serviceToken = obtainProductServiceToken(realm, productId);
        validateRolesExistForProduct(realm, productId, roles, serviceToken);

        try {
            keycloakProductService.assignProductRolesByName(
                    realm, username, productId, serviceToken, roles);
            log.info("External product API assigned {} role(s) to user '{}' for product '{}' in realm '{}'",
                    roles.size(), username, productId, realm);
        } catch (Exception e) {
            log.error("External product API failed to assign roles to user '{}' for product '{}': {}",
                    username, productId, e.getMessage());
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Failed to assign roles: " + e.getMessage(),
                    e);
        }
    }

    /**
     * Validates the product exists and its client secret works (app-to-app), then returns a token
     * that can call Keycloak Admin APIs (master), because product service-account tokens usually
     * lack manage-users unless explicitly configured in Keycloak.
     */
    private String obtainProductServiceToken(String realm, String productId) {
        String masterToken = keycloakProductService.getMasterTokenInternally();
        keycloakProductService.getProductUUID(realm, productId, masterToken);

        String clientSecret = keycloakProductService.getProductSecret(realm, productId, masterToken);
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Product '"
                            + productId
                            + "' has no client secret. Regenerate credentials in Keycloak or recreate the product.");
        }

        try {
            keycloakClient.requestClientCredentialsToken(realm, productId, clientSecret);
            log.debug("Product '{}' client credentials validated for realm '{}'", productId, realm);
        } catch (Exception e) {
            log.warn(
                    "Client credentials check failed for product '{}' in realm '{}': {}",
                    productId,
                    realm,
                    e.getMessage());
        }
        return masterToken;
    }

    private void validateRolesExistForProduct(
            String realm,
            String productId,
            List<AssignRoleRequest> requestedRoles,
            String serviceToken) {
        List<Map<String, Object>> available = keycloakProductService.getProductRoles(realm, productId, serviceToken);
        Set<String> availableNames = available.stream()
                .map(r -> (String) r.get("name"))
                .filter(n -> n != null && !n.isBlank())
                .collect(Collectors.toSet());

        for (AssignRoleRequest role : requestedRoles) {
            String name = role.getName();
            if (name == null || name.isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role name must not be empty");
            }
            if (!availableNames.contains(name)) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "Role '" + name + "' is not defined for product '" + productId + "'");
            }
        }
    }

    private void validateRealmAndProduct(String realm, String productId) {
        if (realm == null || realm.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "realm is required");
        }
        if (productId == null || productId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "productId is required");
        }
    }

    private String requireUsername(Map<String, Object> userPayload) {
        if (userPayload == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Request body is required");
        }
        Object raw = userPayload.get("username");
        if (!(raw instanceof String username) || username.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "username is required in request body");
        }
        return username;
    }
}
