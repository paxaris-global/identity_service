package com.paxaris.identity_service.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.paxaris.identity_service.dto.AssignRoleRequest;
import com.paxaris.identity_service.dto.RoleCreationRequest;
import com.paxaris.identity_service.dto.SignupRequest;
import com.paxaris.identity_service.service.DynamicJwtDecoder;
import com.paxaris.identity_service.service.KeycloakProductService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import org.springframework.http.HttpHeaders;
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

    private static final Logger logger = LoggerFactory.getLogger(KeycloakProductController.class);

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
            @RequestParam(name = "client_id") String clientId,
            @RequestParam(name = "client_secret", required = false) String clientSecret) {

        try {
            Map<String, Object> token = productService.getMyRealmToken(username, password, clientId, realm);
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
            String clientId = credentials.getOrDefault("client_id", "product-service");
            String clientSecret = credentials.getOrDefault("client_secret", null);

            logger.info("🔹 Authenticating user '{}' with clientId '{}'", username, clientId);

            // Get Keycloak token
            Map<String, Object> tokenMap = productService.getMyRealmToken(username, password, clientId, realm);
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

            Map<String, Object> realmAccess = claims.get("realm_access") instanceof Map
                    ? (Map<String, Object>) claims.get("realm_access")
                    : Map.of();

            List<String> realmRoles = realmAccess.get("roles") instanceof List
                    ? ((List<?>) realmAccess.get("roles")).stream()
                    .map(Object::toString)
                    .toList()
                    : List.of();

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

            List<String> allRoles = new ArrayList<>(realmRoles);
            allRoles.addAll(productRoles);

            String extractedRealm = claims.getOrDefault("iss", "").toString();
            if (extractedRealm.contains("/realms/")) {
                extractedRealm = extractedRealm.substring(extractedRealm.lastIndexOf("/realms/") + 8);
            }

            String product = claims.getOrDefault("azp", "").toString();
            String azp = product;

            Map<String, Object> response = new HashMap<>();
            response.put("access_token", keycloakToken);
            response.put("expires_in", tokenMap.get("expires_in"));
            response.put("token_type", tokenMap.get("token_type"));
            response.put("azp", azp);
            response.put("roles", allRoles);
            response.put("realm", extractedRealm);
            response.put("product", product);

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

            Map<String, Object> realmAccess = claims.get("realm_access") instanceof Map
                    ? (Map<String, Object>) claims.get("realm_access")
                    : Map.of();
            List<String> realmRoles = realmAccess.get("roles") instanceof List
                    ? ((List<?>) realmAccess.get("roles")).stream()
                    .map(Object::toString)
                    .toList()
                    : List.of();

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

            List<String> allRoles = new ArrayList<>(realmRoles);
            allRoles.addAll(productRoles);

            String realm = claims.getOrDefault("iss", "").toString();
            if (realm.contains("/realms/")) {
                realm = realm.substring(realm.lastIndexOf("/realms/") + 8);
            }

            String product = claims.getOrDefault("azp", "").toString();

            System.out.println("🔹 Token validated. Realm: " + realm + ", Product: " + product + ", Roles: " + allRoles);

            return ResponseEntity.ok(Map.of(
                    "status", "VALID",
                    "realm", realm,
                    "product", product,
                    "azp", product,
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

    // ------------------- SIGNUP -------------------

    @PostMapping(value = "/signup", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> signup(
            @RequestParam("data") String data,
            @RequestParam("sourceZip") MultipartFile sourceZip) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            SignupRequest request = objectMapper.readValue(data, SignupRequest.class);

            com.paxaris.identity_service.dto.SignupStatus status = productService.signup(request, sourceZip);

            if ("SUCCESS".equals(status.getStatus())) {
                return ResponseEntity.ok(status);
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(status);
            }
        } catch (Exception e) {
            logger.error("Signup failed: {}", e.getMessage(), e);
            com.paxaris.identity_service.dto.SignupStatus errorStatus = com.paxaris.identity_service.dto.SignupStatus
                    .builder()
                    .status("FAILED")
                    .message("Signup failed: " + e.getMessage())
                    .steps(new java.util.ArrayList<>())
                    .build();
            errorStatus.addStep("Signup Process", "FAILED", "Signup failed with exception", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorStatus);
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

    @GetMapping("/identity/realms/user")
    public ResponseEntity<String> getUserRealms(
            @RequestHeader("Authorization") String authorizationHeader
    ) {
        String token = authorizationHeader.startsWith("Bearer ") ? authorizationHeader.substring(7) : authorizationHeader;
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
    @PostMapping("/identity/{realm}/clients")
    public ResponseEntity<String> createProduct(
            @PathVariable String realm,
            @RequestBody Map<String, Object> productRequest) {

        String masterToken = productService.getMyRealmToken(
                "admin", "admin@123", "admin-cli", "master").get("access_token").toString();

        String productId = productRequest.get("clientId").toString();
        boolean publicProduct = Boolean.parseBoolean(
                productRequest.getOrDefault("publicClient", "true").toString());

        try {
            String productUUID = productService.createProduct(realm, productId, publicProduct, masterToken);
            return ResponseEntity.ok("Product created successfully with UUID: " + productUUID);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to create product: " + e.getMessage());
        }
    }

    //------------

    @GetMapping("/client/{realm}/{clientName}/uuid")
    public ResponseEntity<String> getProductUUID(
            @PathVariable String realm,
            @PathVariable String clientName) {
        try {
            String masterToken = productService.getMyRealmToken("admin", "admin123", "admin-cli", "master")
                    .get("access_token").toString();
            String productUUID = productService.getProductUUID(realm, clientName, masterToken);
            return ResponseEntity.ok(productUUID);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to get product UUID: " + e.getMessage());
        }
    }

    // --------- get all products --------------------------------------------

    @GetMapping("/identity/clients/{realm}")
    public ResponseEntity<List<Map<String, Object>>> getAllProducts(
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
            log.error("Failed to get products for realm '{}': {}", realm, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // ------------------- USER -------------------
    @PostMapping("/identity/{realm}/users")
    public ResponseEntity<String> createUser(
            @PathVariable String realm,
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestBody Map<String, Object> userPayload) {

        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
            String userId = productService.createUser(realm, token, userPayload);
            return ResponseEntity.ok(userId);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to create user: " + e.getMessage());
        }
    }

    // --------------------------------get users --------------------------------------
    @GetMapping("identity/users/{realm}")
    public ResponseEntity<List<Map<String, Object>>> getAllUsers(
            @PathVariable String realm,
            @RequestHeader("Authorization") String authorizationHeader) {

        String token = authorizationHeader.startsWith("Bearer ") ? authorizationHeader.substring(7) : authorizationHeader;

        try {
            List<Map<String, Object>> users = productService.getAllUsers(realm, token);
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    // -------------------Create ROLE ok-------------------
    @PostMapping("/identity/{realm}/clients/{clientName}/roles")
    public ResponseEntity<String> createProductRoles(
            @PathVariable String realm,
            @PathVariable String clientName,
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestBody List<RoleCreationRequest> roleRequests) {

        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
            productService.createProductRoles(realm, clientName, roleRequests, token);
            return ResponseEntity.ok("Roles created successfully for product: " + clientName);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to create roles: " + e.getMessage());
        }
    }

    // ------------------- ASSIGN ROLE ok-------------------
    @PostMapping("identity/{realm}/users/{username}/clients/{clientName}/roles")
    public ResponseEntity<String> assignProductRoles(
            @PathVariable String realm,
            @PathVariable String username,
            @PathVariable String clientName,
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestBody List<AssignRoleRequest> rolesBody) {

        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        productService.assignProductRolesByName(
                realm,
                username,
                clientName,
                token,
                rolesBody);

        return ResponseEntity.ok("Product roles assigned successfully");
    }

    //-----------------get client roles
    @GetMapping("/identity/{realm}/clients/{clientName}/roles")
    public ResponseEntity<?> getProductRoles(
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
                    .body("Failed to fetch product roles: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------
    @PutMapping("/identity/role/{realm}/{client}/{roleName}")
    public ResponseEntity<String> updateRole(
            @PathVariable String realm,
            @PathVariable String client,
            @PathVariable String roleName,
            @RequestBody RoleCreationRequest role) {
        try {
            String masterToken = productService.getMyRealmToken("admin", "admin123", "admin-cli", "master")
                    .get("access_token").toString();
            String productUUID = productService.getProductId(realm, client, masterToken);
            boolean ok = productService.updateRole(realm, productUUID, roleName, role, masterToken);
            return ok ? ResponseEntity.ok("Role updated successfully")
                    : ResponseEntity.badRequest().body("Failed to update role");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to update role: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------------------------------------------------------------
    @DeleteMapping("/role/{realm}/{client}/{roleName}")
    public ResponseEntity<String> deleteRole(
            @PathVariable String realm,
            @PathVariable String client,
            @PathVariable String roleName) {
        try {
            String masterToken = productService.getMyRealmToken("admin", "admin123", "admin-cli", "master")
                    .get("access_token").toString();
            String productUUID = productService.getProductId(realm, client, masterToken);
            boolean ok = productService.deleteProductRole(realm, productUUID, roleName, masterToken);
            return ok ? ResponseEntity.ok("Role deleted successfully")
                    : ResponseEntity.badRequest().body("Failed to delete role");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to delete role: " + e.getMessage());
        }
    }



}
