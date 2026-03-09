package com.paxaris.identity_service.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.paxaris.identity_service.dto.*;
import com.paxaris.identity_service.service.DynamicJwtDecoder;
import com.paxaris.identity_service.service.KeycloakProductService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.util.*;

@RestController
@RequestMapping("/")
@RequiredArgsConstructor
@Slf4j
public class KeycloakProductController {

    private final RestTemplate restTemplate = new RestTemplate();
    private final DynamicJwtDecoder jwtDecoder;
    private final KeycloakProductService productService;
    private final ObjectMapper objectMapper;

    @Value("${keycloak.admin-username:admin}")
    private String adminUsername;

    @Value("${keycloak.admin-password}")
    private String adminPassword;

    private static final Logger logger = LoggerFactory.getLogger(KeycloakProductController.class);
    private static final String ADMIN_CLI = "admin-cli";
    private static final String MASTER_REALM = "master";

    // ------------------- TOKEN
    @GetMapping("identity/master/login")
    public ResponseEntity<Map<String, String>> getMasterTokenInternally() {
        String token = productService.getMasterTokenInternally();

        Map<String, String> response = new HashMap<>();
        response.put("access_token", token);

        return ResponseEntity.ok(response);
    }

    // ----------------------------------------------------------------------------------------------------------------------------
    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> getToken(
            @RequestParam String realm,
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam(name = "product_id") String productId,
            @RequestParam(name = "client_secret", required = false) String clientSecret) {

        try {
            Map<String, Object> token = productService.getMyRealmToken(username, password, productId, realm);
            return ResponseEntity.ok(token);
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized", "message", e.getMessage()));
        }
    }

    @PostMapping("/{realm}/login")
    public ResponseEntity<Map<String, Object>> login(
            @PathVariable String realm,
            @RequestBody Map<String, String> credentials) {

        logger.info("🔹 Login request received for realm: {}", realm);
        logger.info("🔹 Received credential keys: {}", credentials.keySet());

        try {
            String username = credentials.get("username");
            String password = credentials.get("password");
            String productId = credentials.getOrDefault("client_id", "product-service");
            String clientSecret = credentials.getOrDefault("client_secret", null);

            logger.info("🔹 Authenticating user '{}' with productId '{}'", username, productId);

            // Get Keycloak token
            Map<String, Object> tokenMap = productService.getMyRealmToken(username, password, productId, realm);
            logger.info("🔹 Keycloak response token map: {}", tokenMap);

            String keycloakToken = (String) tokenMap.get("access_token");
            if (keycloakToken == null) {
                logger.warn("⚠️ Invalid credentials or no token returned by Keycloak");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Invalid credentials"));
            }

            // Decode JWT and extract roles/realm/product
            Jwt decodedJwt = jwtDecoder.decode(keycloakToken);
            Map<String, Object> claims = decodedJwt.getClaims();

            // Safe extraction of realm roles
            Map<String, Object> realmAccess = claims.get("realm_access") instanceof Map
                    ? (Map<String, Object>) claims.get("realm_access")
                    : Map.of();

            List<String> realmRoles = realmAccess.get("roles") instanceof List
                    ? ((List<?>) realmAccess.get("roles")).stream()
                            .map(Object::toString)
                            .toList()
                    : List.of();

            // Safe extraction of product roles
            Map<String, Object> resourceAccess = claims.get("resource_access") instanceof Map
                    ? (Map<String, Object>) claims.get("resource_access")
                    : Map.of();

            List<String> productRoles = new ArrayList<>();

            for (Map.Entry<String, Object> entry : resourceAccess.entrySet()) {
                if (!(entry.getValue() instanceof Map))
                    continue;
                Map<String, Object> productMap = (Map<String, Object>) entry.getValue();
                if (productMap.get("roles") instanceof List<?> rolesList) {
                    rolesList.forEach(r -> productRoles.add(r.toString()));
                }
            }

            // Fetch the redirect url from keycloak and add it to the response
            String redirectUrl = productService.getProductRedirectUrl(realm, productId);

            // Merge roles
            List<String> allRoles = new ArrayList<>(realmRoles);
            allRoles.addAll(productRoles);

            // Extract realm from ISS claim
            String extractedRealm = claims.getOrDefault("iss", "").toString();
            if (extractedRealm.contains("/realms/")) {
                extractedRealm = extractedRealm.substring(extractedRealm.lastIndexOf("/realms/") + 8);
            }

            // Extract product (client_id from azp)
            String product = claims.getOrDefault("azp", "").toString();
            String azp = product;

            // Return token + custom data
            Map<String, Object> response = new HashMap<>();
            response.put("access_token", keycloakToken);
            response.put("expires_in", tokenMap.get("expires_in"));
            response.put("token_type", tokenMap.get("token_type"));
            response.put("azp", azp);
            response.put("roles", allRoles);
            response.put("realm", extractedRealm);
            response.put("product", product);
            response.put("redirect_url", redirectUrl);

            logger.info("✅ Returning login response with roles/realm/product");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("❌ Login failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Login failed", "message", e.getMessage()));
        }
    }
    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "status", "INVALID",
                            "message", "Authorization header missing or malformed"));
        }

        String token = authHeader.substring(7).trim();

        try {
            Jwt decodedJwt = jwtDecoder.decode(token);
            Map<String, Object> claims = decodedJwt.getClaims();

            // --- Safe extraction of realm roles ---
            Map<String, Object> realmAccess = claims.get("realm_access") instanceof Map
                    ? (Map<String, Object>) claims.get("realm_access")
                    : Map.of();
            List<String> realmRoles = realmAccess.get("roles") instanceof List
                    ? ((List<?>) realmAccess.get("roles")).stream()
                            .map(Object::toString)
                            .toList()
                    : List.of();

            // --- Safe extraction of client roles ---
            Map<String, Object> resourceAccess = claims.get("resource_access") instanceof Map
                    ? (Map<String, Object>) claims.get("resource_access")
                    : Map.of();
            List<String> clientRoles = new ArrayList<>();
            for (Map.Entry<String, Object> entry : resourceAccess.entrySet()) {
                if (!(entry.getValue() instanceof Map))
                    continue;
                Map<String, Object> clientMap = (Map<String, Object>) entry.getValue();
                if (clientMap.get("roles") instanceof List<?> rolesList) {
                    rolesList.forEach(r -> clientRoles.add(r.toString()));
                }
            }

            // Merge roles
            List<String> allRoles = new ArrayList<>(realmRoles);
            allRoles.addAll(clientRoles);

            // Extract realm
            String realm = claims.getOrDefault("iss", "").toString();
            if (realm.contains("/realms/")) {
                realm = realm.substring(realm.lastIndexOf("/realms/") + 8);
            }

            // Product = client_id
            // Product = azp (Authorized Party)
            String product = claims.getOrDefault("azp", "").toString();

            // Debug log
            System.out
                    .println("🔹 Token validated. Realm: " + realm + ", Product: " + product + ", Roles: " + allRoles);

            return ResponseEntity.ok(Map.of(
                    "status", "VALID",
                    "realm", realm,
                    "product", product,
                    "azp", product, // ✅ added: include AZP in response
                    "roles", allRoles));

        } catch (Exception e) {
            System.err.println("❌ Token validation failed: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "status", "INVALID",
                            "message", "Token invalid or expired: " + e.getMessage()));
        }
    }

    @GetMapping("/token/validate")
    public ResponseEntity<String> validateToken(
            @RequestParam String realm,
            @RequestHeader("Authorization") String authHeader) {

        String token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;
        boolean valid = productService.validateToken(realm, token);
        return valid ? ResponseEntity.ok("Token is valid") : ResponseEntity.badRequest().body("Token is invalid");
    }

    @PostMapping(value = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SignupStatus> signup(@RequestBody SignupRequest request) {

        try {
                SignupStatus status = productService.signup(
                    request.getRealmName(),
                    request.getAdminPassword()
            );

            return ResponseEntity.ok(status);

        } catch (IllegalArgumentException e) {

            return ResponseEntity.badRequest().body(
                    SignupStatus.builder()
                            .status("FAILED")
                            .message(e.getMessage())
                            .steps(new ArrayList<>())
                            .build()
            );

        } catch (Exception e) {

            SignupStatus errorStatus = SignupStatus.builder()
                    .status("FAILED")
                    .message("Provisioning failed: " + e.getMessage())
                    .steps(new ArrayList<>())
                    .build();

            errorStatus.addStep(
                    "Signup",
                    "FAILED",
                    "Unexpected error",
                    e.getMessage()
            );

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(errorStatus);
        }
    }

    // ------------------- REALM
    // ----------------------------------------------------------------------------------------------------------------------------
    @PostMapping("/realm")
    public ResponseEntity<String> createRealm(@RequestParam String realmName) {
        try {
            String masterToken = productService.getMyRealmToken("admin", "admin123", "admin-cli", "master")
                    .get("access_token").toString();
            productService.createRealm(realmName, masterToken);
            return ResponseEntity.ok("Realm created successfully: " + realmName);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to create realm: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------------------
    @GetMapping("/realms")
    public ResponseEntity<List<Map<String, Object>>> getAllRealms() {
        try {
            String masterToken = productService.getMyRealmToken("admin", "admin123", "admin-cli", "master")
                    .get("access_token").toString();
            return ResponseEntity.ok(productService.getAllRealms(masterToken));
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping("realms/user")
    public ResponseEntity<String> getUserRealms(
            @RequestHeader("Authorization") String authorizationHeader) {
        String token = authorizationHeader.startsWith("Bearer ") ? authorizationHeader.substring(7)
                : authorizationHeader;
        Jwt decodedJwt = jwtDecoder.decode(token);
        Map<String, Object> claims = decodedJwt.getClaims();
        try {
            String realmName = claims.get("azp") instanceof String
                    ? (String) claims.get("azp")
                    : "";
            return ResponseEntity.ok(realmName);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    // ------------------- PRODUCT -------------------
    @PostMapping(
            value = "{realm}/products",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    public ResponseEntity<SignupStatus> createProduct(
            @PathVariable String realm,
            @RequestPart("product") Map<String, Object> productRequest,
            @RequestPart("backendZip") MultipartFile backendZip,
            @RequestPart("frontendZip") MultipartFile frontendZip,
            @RequestPart("frontendBaseUrl") String frontendBaseUrl,
            @RequestHeader("Authorization") String authorizationHeader
    ) {

        // 🔐 User token (identity only)
        String userToken = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        // 🔑 Admin token for Keycloak admin APIs
        String masterToken = productService
                .getMyRealmToken("admin", "admin@123", "admin-cli", "master")
                .get("access_token")
                .toString();

        String productId = productRequest.get("productId").toString();

        boolean publicClient = Boolean.parseBoolean(
                productRequest.getOrDefault("publicClient", "false").toString()
        );

        String username = extractUsernameFromToken(userToken);

        SignupStatus status = SignupStatus.builder()
                .status("IN_PROGRESS")
                .message("Provisioning started")
                .steps(new ArrayList<>())
                .build();

        try {

            productService.createProduct(
                    realm,
                    productId,
                    publicClient,
                    masterToken,
                    backendZip,
                    frontendZip,
                    frontendBaseUrl,   // 👈 redirect URL
                    status,
                    username
            );

            return ResponseEntity.ok(status);

        } catch (Exception e) {
            status.setStatus("FAILED");
            status.setMessage(e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(status);
        }
    }


    private String extractUsernameFromToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getClaimAsString("preferred_username");
        } catch (Exception e) {
            return "system";
        }
    }



    // ---------------------------------get all clients

    @GetMapping("clients/{realm}")
    public ResponseEntity<List<Map<String, Object>>> getAllClients(
            @PathVariable String realm,
            @RequestHeader("Authorization") String authorizationHeader) {

        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
            return ResponseEntity.ok(productService.getAllProducts(realm, token));
        } catch (HttpClientErrorException.Unauthorized e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (HttpClientErrorException.Forbidden e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (Exception e) {
            log.error("Failed to get clients for realm '{}': {}", realm, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // -------------------------------------------------------------------------------------------------------------------------------------------
    @GetMapping("/client/{realm}/{clientName}/uuid")
    public ResponseEntity<String> getClientUUID(
            @PathVariable String realm,
            @PathVariable String clientName) {
        try {
            String masterToken = productService.getMyRealmToken("admin", "admin123", "admin-cli", "master")
                    .get("access_token").toString();
            String clientUUID = productService.getProductUUID(realm, clientName, masterToken);
            return ResponseEntity.ok(clientUUID);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to get client UUID: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------------------------------------------------------------------------------------------------

    // ------------------- USER -------------------
    @PostMapping("{realm}/users")
    public ResponseEntity<String> createUser(
            @PathVariable String realm,
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestBody Map<String, Object> userPayload) {

        // Extract token from the Authorization header
        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
            // Pass the provided token to the service
            String userId = productService.createUser(realm, token, userPayload);
            return ResponseEntity.ok(userId);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to create user: " + e.getMessage());
        }
    }

    // -----------------------------------------------get users------------------------------------------------------------------------------------------------------
    @GetMapping("users/{realm}")
    public ResponseEntity<List<Map<String, Object>>> getAllUsers(
            @PathVariable String realm,
            @RequestHeader("Authorization") String authorizationHeader) {

        String token = authorizationHeader.startsWith("Bearer ") ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
            List<Map<String, Object>> users = productService.getAllUsers(realm, token);
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    // ------------------- ROLE -------------------
    @PostMapping("{realm}/clients/{clientName}/roles")
    public ResponseEntity<String> createClientRoles(
            @PathVariable String realm,
            @PathVariable String clientName,
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestBody List<RoleCreationRequest> roleRequests) {

        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
            productService.createProductRoles(realm, clientName, roleRequests, token);
            return ResponseEntity.ok("Roles created successfully for client: " + clientName);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to create roles: " + e.getMessage());
        }
    }

    @GetMapping("{realm}/clients/{clientName}/roles")
    public ResponseEntity<?> getClientRoles(
            @PathVariable String realm,
            @PathVariable String clientName,
            @RequestHeader("Authorization") String authorizationHeader) {

        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
            List<Map<String, Object>> roles = productService.getProductRoles(realm, clientName, token);

            return ResponseEntity.ok(roles);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to fetch client roles: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------update case -------------------------------------------------------------------------------------
    @PutMapping("role/{realm}/{product}/{roleName}")
    public ResponseEntity<String> updateRole(
            @PathVariable String realm,
            @PathVariable String product,
            @PathVariable String roleName,
            @RequestBody RoleCreationRequest role) {

        try {
            // ✅ Proper admin token
            String masterToken = productService.getMasterTokenInternally();

            boolean ok = productService.updateRole(
                    realm,
                    product,
                    roleName,
                    role,
                    masterToken
            );

            return ok
                    ? ResponseEntity.ok("Role updated successfully")
                    : ResponseEntity.badRequest().body("Failed to update role");

        } catch (Exception e) {
            return ResponseEntity
                    .status(500)
                    .body("Failed to update role: " + e.getMessage());
        }
    }


    // --------------------------------------------------Delete case ---------------------------------------------------------------------------

    @DeleteMapping("role/{realm}/{product}/{roleName}")
    public ResponseEntity<String> deleteProductRole(
            @PathVariable String realm,
            @PathVariable String product,
            @PathVariable String roleName) {

        log.info("➡️ DELETE request received in identity-service");
        log.info("Realm={}, Product={}, Role={}", realm, product, roleName);

        try {
            log.info("🔑 Fetching master token...");
            String masterToken = productService.getMasterTokenInternally();
            log.info("✅ Master token received");

            log.info("🚀 Calling service to delete role...");
            productService.deleteProductRole(
                    realm,
                    product,
                    roleName,
                    masterToken
            );

            log.info("🎯 Delete completed successfully");

            return ResponseEntity.ok("Product role deleted successfully");

        } catch (RuntimeException e) {
            log.error("❌ Business error: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());

        } catch (Exception e) {
            log.error("🔥 System error", e);
            return ResponseEntity.status(500)
                    .body("Failed to delete role: " + e.getMessage());
        }
    }



    // ------------------- ASSIGN ROLE -------------------
    @PostMapping("{realm}/users/{username}/products/{productName}/roles")
    public ResponseEntity<String> assignProductRoles(
            @PathVariable String realm,
            @PathVariable String username,
            @PathVariable String productName,
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestBody List<AssignRoleRequest> rolesBody) {

        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        productService.assignProductRolesByName(
                realm,
                username,
                productName,
                token,
                rolesBody);

        return ResponseEntity.ok("Product roles assigned successfully");
    }

//    -----------------------------------------update the user
@PutMapping("users/{realm}/{username}")
public ResponseEntity<String> updateUser(
        @PathVariable String realm,
        @PathVariable String username,
        @RequestHeader("Authorization") String authorizationHeader,
        @RequestBody Map<String, Object> userPayload) {

    String token = authorizationHeader.startsWith("Bearer ")
            ? authorizationHeader.substring(7)
            : authorizationHeader;

    log.info("➡️ Update request: realm={}, lookupUsername={}", realm, username);
    log.info("📦 Update payload: {}", userPayload);

    productService.updateUser(realm, username, token, userPayload);

    return ResponseEntity.ok("User updated successfully");
}




//--------------------update the user product roles
@PutMapping("{realm}/users/{username}/products/{productName}/roles/{oldRole}")
public ResponseEntity<String> updateUserProductRoles(
        @PathVariable String realm,
        @PathVariable String username,
        @PathVariable String productName,
        @PathVariable String oldRole,
        @RequestBody Map<String, String> body) {

    String newRole = body.get("newRole");

    log.info("➡️ Role swap request: remove='{}', add='{}' for user {}",
            oldRole, newRole, username);

    try {
        String masterToken = productService.getMasterTokenInternally();

        productService.updateUserProductRoles(
                realm,
                username,
                productName,
                oldRole,
                newRole,
                masterToken
        );

        return ResponseEntity.ok("Role updated successfully");

    } catch (Exception e) {
        log.error("❌ Role update failed", e);
        return ResponseEntity.status(500).body(e.getMessage());
    }
}


//-----------------------------delete role from the user product
@DeleteMapping("{realm}/users/{username}/products/{productName}/roles/{roleName}")
public ResponseEntity<String> deleteUserProductRole(
        @PathVariable String realm,
        @PathVariable String username,
        @PathVariable String productName,
        @PathVariable String roleName) {

    log.info("🗑 Delete role request: '{}' for user {}", roleName, username);

    try {
        String masterToken = productService.getMasterTokenInternally();

        productService.deleteUserProductRole(
                realm,
                username,
                productName,
                roleName,
                masterToken
        );

        return ResponseEntity.ok("Role deleted successfully");

    } catch (Exception e) {
        log.error("❌ Role delete failed", e);
        return ResponseEntity.status(500).body(e.getMessage());
    }
}


//----------------------delete user case
    @DeleteMapping("users/{realm}/{username}")
    public ResponseEntity<String> deleteUser(
            @PathVariable String realm,
            @PathVariable String username,
            @RequestHeader("Authorization") String authorizationHeader) {

        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        log.info("🗑 Delete request received: realm={}, username={}", realm, username);

        try {
            productService.deleteUser(realm, username, token);
            return ResponseEntity.ok("User deleted successfully");

        } catch (Exception e) {
            log.error("❌ User delete failed", e);
            return ResponseEntity.status(500).body(e.getMessage());
        }
    }


}

