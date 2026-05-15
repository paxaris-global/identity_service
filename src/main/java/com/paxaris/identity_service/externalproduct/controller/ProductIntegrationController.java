package com.paxaris.identity_service.externalproduct.controller;

import com.paxaris.identity_service.dto.AssignRoleRequest;
import com.paxaris.identity_service.externalproduct.service.ProductIntegrationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * App-to-app APIs for uploaded products. Called from a product's own backend via the API Gateway.
 * <p>
 * Gateway paths (StripPrefix applied):
 * <ul>
 *   <li>{@code POST /identity/product-integration/{realm}/products/{productId}/users}</li>
 *   <li>{@code POST /identity/product-integration/{realm}/products/{productId}/users/{username}/roles}</li>
 * </ul>
 * Paxo dashboard APIs are unchanged; use those as a fallback if integration calls fail.
 */
@RestController
@RequestMapping("/product-integration")
@RequiredArgsConstructor
@Slf4j
@Tag(
        name = "External Product Integration (App-to-App)",
        description = "APIs for uploaded product backends to create users and assign roles without Paxo dashboard")
public class ProductIntegrationController {

    private final ProductIntegrationService productIntegrationService;

    @PostMapping("/{realm}/products/{productId}/users")
    @Operation(
            summary = "Create user for an uploaded product (app-to-app)",
            description = "Creates a user in the Keycloak realm for the given product. "
                    + "Uses the product client_id and client secret (server-side). "
                    + "Intended for product backends, not Paxo dashboard.")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "User created"),
            @ApiResponse(responseCode = "409", description = "Username already exists"),
            @ApiResponse(responseCode = "400", description = "Invalid request or product not found")
    })
    public ResponseEntity<Map<String, Object>> createUser(
            @Parameter(description = "Keycloak realm name", example = "vipultest")
            @PathVariable String realm,
            @Parameter(description = "Product client_id (Keycloak client id)", example = "myshop-app")
            @PathVariable String productId,
            @RequestBody Map<String, Object> userPayload) {

        log.info("External product integration create user: realm={}, product={}", realm, productId);
        String userId = productIntegrationService.createProductUser(realm, productId, userPayload);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("userId", userId);
        body.put("realm", realm);
        body.put("productId", productId);
        body.put("username", userPayload.get("username"));
        body.put("message", "User created successfully");

        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    @PostMapping("/{realm}/products/{productId}/users/{username}/roles")
    @Operation(
            summary = "Assign product roles to a user (app-to-app)",
            description = "Assigns one or more client roles for the product to the user. "
                    + "Validates that each role exists on the product before assignment.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Roles assigned"),
            @ApiResponse(responseCode = "400", description = "User/role not found or invalid request")
    })
    public ResponseEntity<Map<String, String>> assignRoles(
            @PathVariable String realm,
            @PathVariable String productId,
            @PathVariable String username,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Roles to assign",
                    required = true,
                    content = @Content(schema = @Schema(example = "[{\"name\": \"customer\"}]")))
            @RequestBody List<AssignRoleRequest> roles) {

        log.info("External product integration assign roles: realm={}, product={}, user={}",
                realm, productId, username);
        productIntegrationService.assignProductUserRoles(realm, productId, username, roles);

        return ResponseEntity.ok(Map.of(
                "message", "Product roles assigned successfully",
                "realm", realm,
                "productId", productId,
                "username", username));
    }
}
