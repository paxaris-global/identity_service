package com.paxaris.identity_service.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.paxaris.identity_service.dto.*;
import com.paxaris.identity_service.service.DynamicJwtDecoder;
import com.paxaris.identity_service.service.KeycloakProductService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@RestController
@RequestMapping({"/", "/api/v1/identity"})
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Identity Service", description = "APIs for authentication, authorization, and user/product management with Keycloak")
public class KeycloakProductController {

        private final RestTemplate restTemplate;
    private final DynamicJwtDecoder jwtDecoder;
    private final KeycloakProductService productService;
    private final ObjectMapper objectMapper;

        @Value("${keycloak.admin-username}")
    private String adminUsername;

    @Value("${keycloak.admin-password}")
    private String adminPassword;

        @Value("${keycloak.client-id}")
    private String keycloakClientId;

        @Value("${keycloak.master-realm}")
    private String masterRealm;

        @Value("${identity.login.default-product-id}")
        private String defaultLoginProductId;

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
            @RequestParam(name = "product_id") String productId) {

        try {
            Map<String, Object> token = productService.getMyRealmToken(username, password, productId, realm);
            return ResponseEntity.ok(token);
        } catch (Exception e) {
                        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, e.getMessage(), e);
        }
    }

    @PostMapping("/{realm}/login")
    @Operation(
            summary = "User Login with Enhanced Response",
            description = "Authenticates a user and returns JWT token with roles, realm info, and redirect URL. " +
                    "This is the primary login endpoint that provides complete authentication details."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Login successful - Returns token with user roles and metadata",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    {
                                      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI...",
                                      "expires_in": 300,
                                      "token_type": "Bearer",
                                      "azp": "my-product",
                                      "roles": ["admin", "user", "product-manager"],
                                      "realm": "my-realm",
                                      "product": "my-product",
                                      "redirect_url": "https://myapp.example.com/dashboard"
                                    }
                                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized - Invalid credentials",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    {
                                      "error": "Invalid credentials"
                                    }
                                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    {
                                      "error": "Login failed",
                                      "message": "Connection to Keycloak failed"
                                    }
                                    """)
                    )
            )
    })
    public ResponseEntity<Map<String, Object>> login(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Login credentials including username, password, and optional product details",
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    {
                                      "username": "admin@example.com",
                                      "password": "password123",
                                                                                                                                                        "product_id": "my-product",
                                                                                                                                                        "product_secret": "optional-secret"
                                    }
                                    """)
                    )
            )
            @org.springframework.web.bind.annotation.RequestBody Map<String, String> credentials) {

        logger.info("🔹 Login request received for realm: {}", realm);
        logger.info("🔹 Received credential keys: {}", credentials.keySet());

        try {
            String username = credentials.get("username");
            String password = credentials.get("password");
                        String productId = credentials.getOrDefault("product_id",
                                        credentials.getOrDefault("client_id", defaultLoginProductId));

            logger.info("🔹 Authenticating user '{}' with productId '{}'", username, productId);

            // Get Keycloak token
            Map<String, Object> tokenMap = productService.getMyRealmToken(username, password, productId, realm);
            logger.info("🔹 Keycloak response token map: {}", tokenMap);

            String keycloakToken = (String) tokenMap.get("access_token");
            if (keycloakToken == null) {
                logger.warn("⚠️ Invalid credentials or no token returned by Keycloak");
                                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
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


                        // Admin detection: at least 3 of 5 main admin roles or any role containing 'admin'
                        Set<String> normalizedRoles = allRoles.stream().map(r -> r.trim().toLowerCase()).collect(java.util.stream.Collectors.toSet());
                        String[] adminRoles = {"create-client", "impersonation", "manage-clients", "manage-realm", "manage-users", "admin"};
                        int adminMatch = 0;
                        for (String role : adminRoles) {
                                if (normalizedRoles.contains(role)) adminMatch++;
                        }
                        boolean isAdmin = adminMatch >= 3 || normalizedRoles.stream().anyMatch(r -> r.contains("admin"));

                        // Return token + custom data
                        Map<String, Object> response = new HashMap<>();
                        response.put("access_token", keycloakToken);
                        response.put("expires_in", tokenMap.get("expires_in"));
                        response.put("token_type", tokenMap.get("token_type"));
                        response.put("refresh_token", tokenMap.get("refresh_token"));
                        response.put("refresh_expires_in", tokenMap.get("refresh_expires_in"));
                        response.put("scope", tokenMap.get("scope"));
                        response.put("azp", azp);
                        response.put("roles", allRoles);
                        response.put("realm", extractedRealm);
                        response.put("product", product);
                        response.put("redirect_url", redirectUrl);
                        response.put("isAdmin", isAdmin);

                        logger.info("✅ Returning login response with roles/realm/product, isAdmin={}", isAdmin);

                        return ResponseEntity.ok(response);

                } catch (HttpClientErrorException.Unauthorized e) {
                        logger.warn("Invalid credentials for realm {}: {}", realm, e.getMessage());
                        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials", e);
                } catch (Exception e) {
            logger.error("❌ Login failed: {}", e.getMessage(), e);
                        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                                        "Login failed: " + e.getMessage(), e);
        }
    }

        @PostMapping("/{realm}/refresh")
        public ResponseEntity<Map<String, Object>> refreshToken(
                        @PathVariable String realm,
                        @org.springframework.web.bind.annotation.RequestBody Map<String, String> payload) {
                String refreshToken = payload.get("refresh_token");
                String productId = payload.getOrDefault("product_id", payload.getOrDefault("client_id", defaultLoginProductId));

                if (refreshToken == null || refreshToken.isBlank()) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "refresh_token is required");
                }

                try {
                        Map<String, Object> tokenMap = productService.refreshMyRealmToken(refreshToken, productId, realm);

                        Map<String, Object> response = new HashMap<>();
                        response.put("access_token", tokenMap.get("access_token"));
                        response.put("expires_in", tokenMap.get("expires_in"));
                        response.put("token_type", tokenMap.get("token_type"));
                        response.put("refresh_token", tokenMap.getOrDefault("refresh_token", refreshToken));
                        response.put("refresh_expires_in", tokenMap.get("refresh_expires_in"));
                        response.put("scope", tokenMap.get("scope"));

                        return ResponseEntity.ok(response);
                } catch (HttpClientErrorException.Unauthorized e) {
                        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token", e);
                } catch (IllegalArgumentException e) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
                } catch (Exception e) {
                        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token failed", e);
                }
        }

    @GetMapping("/validate")
    @Operation(
            summary = "Validate JWT Token",
            description = "Validates a JWT token and extracts user claims including roles, realm, and product information"
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token is valid - Returns token claims",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    {
                                      "status": "VALID",
                                      "realm": "my-realm",
                                      "product": "my-product",
                                      "azp": "my-product",
                                      "roles": ["admin", "user"]
                                    }
                                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Token is invalid or expired",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    {
                                      "status": "INVALID",
                                      "message": "Token invalid or expired: JWT expired at 2026-03-10T10:00:00Z"
                                    }
                                    """)
                    )
            )
    })
    public ResponseEntity<Map<String, Object>> validateToken(
            @Parameter(description = "JWT Bearer token in Authorization header", required = true)
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Authorization header missing or malformed");
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

                        // --- Safe extraction of product roles ---
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

            // Merge roles
            List<String> allRoles = new ArrayList<>(realmRoles);
                        allRoles.addAll(productRoles);

            // Extract realm
            String realm = claims.getOrDefault("iss", "").toString();
            if (realm.contains("/realms/")) {
                realm = realm.substring(realm.lastIndexOf("/realms/") + 8);
            }

            // Product = azp (Authorized Party)
            String product = claims.getOrDefault("azp", "").toString();

            log.debug("Token validated realm={} product={} roles={}", realm, product, allRoles);

            return ResponseEntity.ok(Map.of(
                    "status", "VALID",
                    "realm", realm,
                    "product", product,
                    "azp", product, // ✅ added: include AZP in response
                    "roles", allRoles));

                } catch (Exception e) {
                        log.warn("Token validation failed: {}", e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Token invalid or expired: " + e.getMessage(), e);
        }
    }

    @GetMapping("/token/validate")
    @Operation(
            summary = "Simple Token Validation",
            description = "Simple boolean validation of JWT token for a specific realm"
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token is valid"),
            @ApiResponse(responseCode = "400", description = "Token is invalid")
    })
    public ResponseEntity<String> validateToken(
            @Parameter(description = "Realm name", required = true, example = "my-realm")
            @RequestParam String realm,
            @Parameter(description = "JWT Bearer token", required = true)
            @RequestHeader("Authorization") String authHeader) {

        String token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;
        boolean valid = productService.validateToken(realm, token);
                if (!valid) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token is invalid");
                }
                return ResponseEntity.ok("Token is valid");
    }

    @PostMapping(value = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "Complete Signup with Realm Provisioning",
            description = "Creates a new Keycloak realm with initial admin user and admin product. " +
                    "This is a comprehensive signup process that sets up the complete multi-tenant environment."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "Signup completed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SignupStatus.class, example = """
                                    {
                                      "status": "SUCCESS",
                                      "message": "Provisioning completed successfully",
                                      "steps": [
                                        {
                                          "stepName": "Create Realm",
                                          "status": "SUCCESS",
                                          "message": "Realm created"
                                        },
                                        {
                                          "stepName": "Create Admin User",
                                          "status": "SUCCESS",
                                          "message": "Admin user created"
                                        },
                                        {
                                          "stepName": "Create Admin Product",
                                          "status": "SUCCESS",
                                          "message": "Admin product created"
                                        }
                                      ],
                                      "token": {
                                        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI...",
                                        "expires_in": 300
                                      }
                                    }
                                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Bad request - Invalid input parameters",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SignupStatus.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Conflict - realm or admin product already exists",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SignupStatus.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Provisioning failed",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SignupStatus.class)
                    )
            )
    })
    public ResponseEntity<SignupStatus> signup(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Signup request with realm name and admin password",
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SignupRequest.class, example = """
                                    {
                                      "realmName": "my-company",
                                      "adminPassword": "SecureAdminPassword@123",
                                      "adminUsername": "admin"
                                    }
                                    """)
                    )
            )
            @org.springframework.web.bind.annotation.RequestBody SignupRequest request) {

        try {
                SignupStatus status = productService.signup(
                    request.getRealmName(),
                    request.getAdminPassword()
            );

                        if ("SUCCESS".equalsIgnoreCase(status.getStatus())) {
                                return ResponseEntity.status(HttpStatus.CREATED).body(status);
                        }

                        if (isConflictStatus(status)) {
                                return ResponseEntity.status(HttpStatus.CONFLICT).body(status);
                        }

                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(status);

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
    @Operation(
            summary = "Create New Realm",
            description = "Creates a new Keycloak realm for tenant isolation"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Realm created successfully",
                    content = @Content(schema = @Schema(example = "Realm created successfully: my-realm"))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Failed to create realm",
                    content = @Content(schema = @Schema(example = "Failed to create realm: Realm already exists"))
            )
    })
    public ResponseEntity<String> createRealm(
            @Parameter(description = "Unique name for the new realm", required = true, example = "my-company-realm")
            @RequestParam String realmName) {
        try {
            String masterToken = productService.getMyRealmToken(adminUsername, adminPassword, keycloakClientId, masterRealm)
                    .get("access_token").toString();
            productService.createRealm(realmName, masterToken);
            return ResponseEntity.ok("Realm created successfully: " + realmName);
        } catch (Exception e) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                                        "Failed to create realm: " + e.getMessage(), e);
        }
    }

    // -------------------------------------------------------------------------------------
    @GetMapping("/realms")
    @Operation(
            summary = "Get All Realms",
            description = "Retrieves a list of all configured Keycloak realms"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Realms retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    [
                                      {
                                        "id": "realm-id-123",
                                        "realm": "my-realm",
                                        "displayName": "My Company Realm",
                                        "enabled": true
                                      }
                                    ]
                                    """)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Failed to retrieve realms")
    })
    public ResponseEntity<List<Map<String, Object>>> getAllRealms() {
        try {
            String masterToken = productService.getMyRealmToken(adminUsername, adminPassword, keycloakClientId, masterRealm)
                    .get("access_token").toString();
            return ResponseEntity.ok(productService.getAllRealms(masterToken));
        } catch (Exception e) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                                        "Failed to retrieve realms: " + e.getMessage(), e);
        }
    }

    @GetMapping("realms/user")
    @Operation(
            summary = "Get User's Realm",
            description = "Retrieves the realm name associated with the authenticated user's token"
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Realm name retrieved successfully",
                    content = @Content(schema = @Schema(example = "my-realm"))
            ),
            @ApiResponse(responseCode = "400", description = "Failed to retrieve realm")
    })
    public ResponseEntity<String> getUserRealms(
            @Parameter(description = "JWT Bearer token", required = true)
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
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                                        "Failed to retrieve realm from token: " + e.getMessage(), e);
        }
    }

    // ------------------- PRODUCT -------------------
    @PostMapping(
            value = "{realm}/products",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    @Operation(
            summary = "Create Product with Deployment",
            description = "Creates a new product in Keycloak and deploys backend/frontend applications. " +
                    "This endpoint handles complete product provisioning including Docker deployment and GitHub repository setup."
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "Product created and deployed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SignupStatus.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Conflict - product/client already exists",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SignupStatus.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Product creation failed",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SignupStatus.class)
                    )
            )
    })
    public ResponseEntity<SignupStatus> createProduct(
            @Parameter(description = "Realm name where product will be created", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "Product configuration JSON", required = true)
            @RequestPart("product") Map<String, Object> productRequest,
            @Parameter(description = "Backend application ZIP file", required = true)
            @RequestPart("backendZip") MultipartFile backendZip,
            @Parameter(description = "Frontend application ZIP file", required = true)
            @RequestPart("frontendZip") MultipartFile frontendZip,
            @Parameter(description = "Frontend base URL/redirect URI", required = true, example = "https://myapp.example.com")
            @RequestPart("frontendBaseUrl") String frontendBaseUrl,
            @Parameter(description = "JWT Bearer token", required = true)
            @RequestHeader("Authorization") String authorizationHeader
    ) {

        // 🔐 User token (identity only)
        String userToken = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        // 🔑 Admin token for Keycloak admin APIs
        String masterToken = productService
                .getMyRealmToken(adminUsername, adminPassword, keycloakClientId, masterRealm)
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

                        return ResponseEntity.status(HttpStatus.CREATED).body(status);

        } catch (Exception e) {
            status.setStatus("FAILED");
            status.setMessage(e.getMessage());

                        if (isConflictException(e)) {
                                return ResponseEntity.status(HttpStatus.CONFLICT).body(status);
                        }

                        if (isServiceUnavailableException(e)) {
                                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(status);
                        }

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

        private boolean isConflictStatus(SignupStatus status) {
                if (status == null) {
                        return false;
                }
                String message = status.getMessage();
                return message != null &&
                                (message.toLowerCase().contains("already exists") || message.toLowerCase().contains("conflict"));
        }

        private boolean isConflictException(Throwable throwable) {
                Throwable current = throwable;
                while (current != null) {
                        if (current instanceof HttpClientErrorException clientError
                                        && clientError.getStatusCode() == HttpStatus.CONFLICT) {
                                return true;
                        }

                        String message = current.getMessage();
                        if (message != null) {
                                String normalized = message.toLowerCase();
                                if (normalized.contains("already exists") || normalized.contains("409") || normalized.contains("conflict")) {
                                        return true;
                                }
                        }
                        current = current.getCause();
                }
                return false;
        }

        private boolean isServiceUnavailableException(Throwable throwable) {
                Throwable current = throwable;
                while (current != null) {
                        if (current instanceof org.springframework.web.client.HttpStatusCodeException statusCodeException
                                        && statusCodeException.getStatusCode() == HttpStatus.SERVICE_UNAVAILABLE) {
                                return true;
                        }

                        String message = current.getMessage();
                        if (message != null) {
                                String normalized = message.toLowerCase();
                                if (normalized.contains("service unavailable")
                                                || normalized.contains("github_token missing")
                                                || normalized.contains("configuration error")) {
                                        return true;
                                }
                        }
                        current = current.getCause();
                }
                return false;
        }



    // ---------------------------------get all products

    @GetMapping("products/{realm}")
    @Operation(
            summary = "Get All Products",
            description = "Retrieves a list of all products configured in the specified realm"
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Products retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    [
                                      {
                                        "id": "client-id-123",
                                        "clientId": "my-product",
                                        "name": "My Product",
                                        "description": "Product description",
                                        "enabled": true,
                                        "publicClient": true,
                                        "redirectUris": ["https://myapp.example.com/*"],
                                        "webOrigins": ["https://myapp.example.com"]
                                      }
                                    ]
                                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized - Invalid or missing token"
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Forbidden - Insufficient permissions"
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error"
            )
    })
        public ResponseEntity<List<Map<String, Object>>> getAllProducts(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "JWT Bearer token", required = true)
            @RequestHeader("Authorization") String authorizationHeader) {

        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
            return ResponseEntity.ok(productService.getAllProducts(realm, token));
        } catch (HttpClientErrorException.Unauthorized e) {
                        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired token", e);
        } catch (HttpClientErrorException.Forbidden e) {
                        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Insufficient permissions", e);
        } catch (Exception e) {
            log.error("Failed to get products for realm '{}': {}", realm, e.getMessage());
                        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                                        "Failed to get products: " + e.getMessage(), e);
        }
    }

    // -------------------------------------------------------------------------------------------------------------------------------------------
    @GetMapping("/product/{realm}/{productName}/uuid")
    @Operation(
            summary = "Get Product UUID",
            description = "Retrieves the internal UUID of a product by its product ID name"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Product UUID retrieved successfully",
                    content = @Content(schema = @Schema(example = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Failed to get product UUID",
                    content = @Content(schema = @Schema(example = "Failed to get product UUID: Product not found"))
            )
    })
    public ResponseEntity<String> getProductUUID(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "Product name", required = true, example = "my-product")
            @PathVariable String productName) {
        try {
            String masterToken = productService.getMyRealmToken(adminUsername, adminPassword, keycloakClientId, masterRealm)
                    .get("access_token").toString();
            String productUUID = productService.getProductUUID(realm, productName, masterToken);
            return ResponseEntity.ok(productUUID);
        } catch (Exception e) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                                        "Failed to get product UUID: " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------------------------------------------------------------------------------------------------

    // ------------------- USER -------------------
    @PostMapping("{realm}/users")
    @Operation(
            summary = "Create New User",
            description = "Creates a new user in the specified Keycloak realm with the provided user details"
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "User created successfully - Returns user ID",
                    content = @Content(schema = @Schema(example = "user-id-12345"))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Failed to create user",
                    content = @Content(schema = @Schema(example = "Failed to create user: Username already exists"))
            )
    })
    public ResponseEntity<String> createUser(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "JWT Bearer token", required = true)
            @RequestHeader("Authorization") String authorizationHeader,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "User details for creation",
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    {
                                      "username": "john.doe",
                                      "email": "john.doe@example.com",
                                      "firstName": "John",
                                      "lastName": "Doe",
                                      "enabled": true,
                                      "emailVerified": false,
                                      "credentials": [{
                                        "type": "password",
                                        "value": "SecurePassword123",
                                        "temporary": false
                                      }]
                                    }
                                    """)
                    )
            )
            @org.springframework.web.bind.annotation.RequestBody Map<String, Object> userPayload) {

        // Extract token from the Authorization header
        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
            // Pass the provided token to the service
            String userId = productService.createUser(realm, token, userPayload);
            return ResponseEntity.ok(userId);
        } catch (Exception e) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                                        "Failed to create user: " + e.getMessage(), e);
        }
    }

    // -----------------------------------------------get users------------------------------------------------------------------------------------------------------
    @GetMapping("users/{realm}")
    @Operation(
            summary = "Get All Users",
            description = "Retrieves a list of all users in the specified realm with their details"
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Users retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    [
                                      {
                                        "id": "user-id-123",
                                        "username": "john.doe",
                                        "email": "john.doe@example.com",
                                        "firstName": "John",
                                        "lastName": "Doe",
                                        "enabled": true,
                                        "emailVerified": true,
                                        "createdTimestamp": 1709971200000
                                      }
                                    ]
                                    """)
                    )
            ),
            @ApiResponse(responseCode = "400", description = "Failed to retrieve users")
    })
    public ResponseEntity<List<Map<String, Object>>> getAllUsers(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "JWT Bearer token", required = true)
            @RequestHeader("Authorization") String authorizationHeader) {

        String token = authorizationHeader.startsWith("Bearer ") ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
            List<Map<String, Object>> users = productService.getAllUsers(realm, token);
            return ResponseEntity.ok(users);
        } catch (Exception e) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                                        "Failed to retrieve users: " + e.getMessage(), e);
        }
    }

    // ------------------- ROLE -------------------
    @PostMapping("{realm}/products/{productName}/roles")
    @Operation(
            summary = "Create Product Roles",
            description = "Creates one or more roles for a specific product with optional URIs and HTTP methods for API access control"
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Roles created successfully",
                    content = @Content(schema = @Schema(example = "Roles created successfully for product: my-product"))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Failed to create roles",
                    content = @Content(schema = @Schema(example = "Failed to create roles: Role already exists"))
            )
    })
    public ResponseEntity<String> createProductRoles(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "Product name", required = true, example = "my-product")
            @PathVariable String productName,
            @Parameter(description = "JWT Bearer token", required = true)
            @RequestHeader("Authorization") String authorizationHeader,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "List of roles to create with optional metadata",
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = RoleCreationRequest.class, example = """
                                    [
                                      {
                                        "name": "admin",
                                        "description": "Administrator role with full access",
                                        "uri": "/api/admin/*",
                                        "httpMethod": "GET"
                                      },
                                      {
                                        "name": "user",
                                        "description": "Standard user role",
                                        "uri": "/api/user/*",
                                        "httpMethod": "GET"
                                      }
                                    ]
                                    """)
                    )
            )
            @org.springframework.web.bind.annotation.RequestBody List<RoleCreationRequest> roleRequests) {

        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
            productService.createProductRoles(realm, productName, roleRequests, token);
            return ResponseEntity.ok("Roles created successfully for product: " + productName);
        } catch (Exception e) {
                        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                                        "Failed to create roles: " + e.getMessage(), e);
        }
    }

    @GetMapping("{realm}/products/{productName}/roles")
    @Operation(
            summary = "Get Product Roles",
            description = "Retrieves all roles configured for a specific product"
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Roles retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    [
                                      {
                                        "id": "role-id-123",
                                        "name": "admin",
                                        "description": "Administrator role",
                                        "composite": false,
                                        "clientRole": true,
                                        "containerId": "client-id-456"
                                      },
                                      {
                                        "id": "role-id-789",
                                        "name": "user",
                                        "description": "Standard user role",
                                        "composite": false,
                                        "clientRole": true,
                                        "containerId": "client-id-456"
                                      }
                                    ]
                                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Failed to fetch roles",
                    content = @Content(schema = @Schema(example = "Failed to fetch product roles: Product not found"))
            )
    })
    public ResponseEntity<?> getProductRoles(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "Product name", required = true, example = "my-product")
            @PathVariable String productName,
            @Parameter(description = "JWT Bearer token", required = true)
            @RequestHeader("Authorization") String authorizationHeader) {

        String token = authorizationHeader.startsWith("Bearer ")
                ? authorizationHeader.substring(7)
                : authorizationHeader;

        try {
                        List<Map<String, Object>> roles = productService.getProductRoles(realm, productName, token);

            return ResponseEntity.ok(roles);
        } catch (Exception e) {
                        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                                                                                "Failed to fetch product roles: " + e.getMessage(), e);
        }
    }

    // ---------------------------------------------------------update case -------------------------------------------------------------------------------------
    @PutMapping("role/{realm}/{product}/{roleName}")
    @Operation(
            summary = "Update Product Role",
            description = "Updates an existing role's details including name, description, URI, and HTTP method for a product"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Role updated successfully",
                    content = @Content(schema = @Schema(example = "Role updated successfully"))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Failed to update role",
                    content = @Content(schema = @Schema(example = "Failed to update role"))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(schema = @Schema(example = "Failed to update role: Connection timeout"))
            )
    })
    public ResponseEntity<String> updateRole(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "Product name", required = true, example = "my-product")
            @PathVariable String product,
            @Parameter(description = "Current role name to update", required = true, example = "admin")
            @PathVariable String roleName,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Updated role details",
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = RoleCreationRequest.class, example = """
                                    {
                                      "name": "super-admin",
                                      "description": "Super administrator with extended privileges",
                                      "uri": "/api/admin/**",
                                      "httpMethod": "POST"
                                    }
                                    """)
                    )
            )
            @org.springframework.web.bind.annotation.RequestBody RoleCreationRequest role) {

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

            if (!ok) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Failed to update role");
            }
            return ResponseEntity.ok("Role updated successfully");

        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to update role: " + e.getMessage(), e);
        }
    }


    // --------------------------------------------------Delete case ---------------------------------------------------------------------------

    @DeleteMapping("role/{realm}/{product}/{roleName}")
    @Operation(
            summary = "Delete Product Role",
            description = "Permanently deletes a role from a product. This action cannot be undone."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Role deleted successfully",
                    content = @Content(schema = @Schema(example = "Product role deleted successfully"))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Business error - Role not found or in use",
                    content = @Content(schema = @Schema(example = "Role not found: admin"))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "System error",
                    content = @Content(schema = @Schema(example = "Failed to delete role: Internal server error"))
            )
    })
    public ResponseEntity<String> deleteProductRole(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "Product name", required = true, example = "my-product")
            @PathVariable String product,
            @Parameter(description = "Role name to delete", required = true, example = "admin")
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
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);

        } catch (Exception e) {
            log.error("🔥 System error", e);
                        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                                        "Failed to delete role: " + e.getMessage(), e);
        }
    }



    // ------------------- ASSIGN ROLE -------------------
    @PostMapping("/{realm}/users/{username}/products/{productName}/roles")
    @Operation(
            summary = "Assign Product Roles to User",
            description = "Assigns one or more product-specific roles to a user. " +
                    "This grants the user access rights defined by the assigned roles for the specified product."
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Roles assigned successfully",
                    content = @Content(schema = @Schema(example = "Product roles assigned successfully"))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Failed to assign roles - User or role not found",
                    content = @Content(schema = @Schema(example = "Failed to assign roles: User not found"))
            )
    })
    public ResponseEntity<String> assignProductRoles(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "Username to assign roles to", required = true, example = "john.doe")
            @PathVariable String username,
            @Parameter(description = "Product name", required = true, example = "my-product")
            @PathVariable String productName,
            @Parameter(description = "JWT Bearer token", required = true)
            @RequestHeader("Authorization") String authorizationHeader,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "List of roles to assign to the user",
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AssignRoleRequest.class, example = """
                                    [
                                      {"name": "admin"},
                                      {"name": "user"},
                                      {"name": "manager"}
                                    ]
                                    """)
                    )
            )
            @org.springframework.web.bind.annotation.RequestBody List<AssignRoleRequest> rolesBody) {

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
@Operation(
        summary = "Update User Profile",
        description = "Updates user profile information including email, first name, last name, and other attributes"
)
@SecurityRequirement(name = "bearer")
@ApiResponses(value = {
        @ApiResponse(
                responseCode = "200",
                description = "User updated successfully",
                content = @Content(schema = @Schema(example = "User updated successfully"))
        ),
        @ApiResponse(
                responseCode = "400",
                description = "Failed to update user - User not found or invalid data",
                content = @Content(schema = @Schema(example = "Failed to update user: User not found"))
        )
})
public ResponseEntity<String> updateUser(
        @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
        @PathVariable String realm,
        @Parameter(description = "Username to update", required = true, example = "john.doe")
        @PathVariable String username,
        @Parameter(description = "JWT Bearer token", required = true)
        @RequestHeader("Authorization") String authorizationHeader,
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "User profile fields to update",
                required = true,
                content = @Content(
                        mediaType = "application/json",
                        schema = @Schema(example = """
                                {
                                  "email": "john.doe.new@example.com",
                                  "firstName": "John",
                                  "lastName": "Doe Updated",
                                  "enabled": true,
                                  "emailVerified": true
                                }
                                """))
        )
        @org.springframework.web.bind.annotation.RequestBody Map<String, Object> userPayload) {

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
@Operation(
        summary = "Update User's Product Role",
        description = "Swaps a user's existing role with a new role for a specific product. " +
                "This removes the old role and assigns the new role in a single operation."
)
@ApiResponses(value = {
        @ApiResponse(
                responseCode = "200",
                description = "Role updated successfully",
                content = @Content(schema = @Schema(example = "Role updated successfully"))
        ),
        @ApiResponse(
                responseCode = "500",
                description = "Role update failed",
                content = @Content(schema = @Schema(example = "Role update failed: Old role not found"))
        )
})
public ResponseEntity<String> updateUserProductRoles(
        @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
        @PathVariable String realm,
        @Parameter(description = "Username", required = true, example = "john.doe")
        @PathVariable String username,
        @Parameter(description = "Product name", required = true, example = "my-product")
        @PathVariable String productName,
        @Parameter(description = "Current role name to be removed", required = true, example = "user")
        @PathVariable String oldRole,
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
                description = "New role to assign",
                required = true,
                content = @Content(
                        mediaType = "application/json",
                        schema = @Schema(example = """
                                {
                                  "newRole": "admin"
                                }
                                """))
        )
        @org.springframework.web.bind.annotation.RequestBody Map<String, String> body) {

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
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                                "Role update failed: " + e.getMessage(), e);
    }
}


//-----------------------------delete role from the user product
@DeleteMapping("{realm}/users/{username}/products/{productName}/roles/{roleName}")
@Operation(
        summary = "Remove Role from User",
        description = "Removes a specific product role from a user. The user will lose access rights associated with this role."
)
@ApiResponses(value = {
        @ApiResponse(
                responseCode = "200",
                description = "Role removed successfully",
                content = @Content(schema = @Schema(example = "Role deleted successfully"))
        ),
        @ApiResponse(
                responseCode = "500",
                description = "Role deletion failed",
                content = @Content(schema = @Schema(example = "Role deletion failed: User does not have this role"))
        )
})
public ResponseEntity<String> deleteUserProductRole(
        @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
        @PathVariable String realm,
        @Parameter(description = "Username", required = true, example = "john.doe")
        @PathVariable String username,
        @Parameter(description = "Product name", required = true, example = "my-product")
        @PathVariable String productName,
        @Parameter(description = "Role name to remove from user", required = true, example = "admin")
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
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                                "Role delete failed: " + e.getMessage(), e);
    }
}


//----------------------delete user case
    @DeleteMapping("users/{realm}/{username}")
    @Operation(
            summary = "Delete User Account",
            description = "Permanently deletes a user from the realm. This action removes all user data and cannot be undone."
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "User deleted successfully",
                    content = @Content(schema = @Schema(example = "User deleted successfully"))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "User deletion failed",
                    content = @Content(schema = @Schema(example = "User deletion failed: User not found"))
            )
    })
    public ResponseEntity<String> deleteUser(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "Username to delete", required = true, example = "john.doe")
            @PathVariable String username,
            @Parameter(description = "JWT Bearer token", required = true)
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
                        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                                        "User delete failed: " + e.getMessage(), e);
        }
    }


}

