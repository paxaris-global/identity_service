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

import java.util.*;

@RestController
@RequestMapping("/")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Identity Service", description = "APIs for authentication, authorization, and user/product management with Keycloak")
public class KeycloakProductController {

    private final RestTemplate restTemplate = new RestTemplate();
    private final DynamicJwtDecoder jwtDecoder;
    private final KeycloakProductService productService;
    private final ObjectMapper objectMapper;

    @Value("${keycloak.admin-username:admin}")
    private String adminUsername;

    @Value("${keycloak.admin-password}")
    private String adminPassword;

    @Value("${keycloak.client-id:admin-cli}")
    private String keycloakClientId;

    @Value("${keycloak.master-realm:master}")
    private String masterRealm;

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
                    description = "Login credentials including username, password, and optional client details",
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(example = """
                                    {
                                      "username": "admin@example.com",
                                      "password": "password123",
                                      "client_id": "my-product",
                                      "client_secret": "optional-secret"
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
        return valid ? ResponseEntity.ok("Token is valid") : ResponseEntity.badRequest().body("Token is invalid");
    }

    @PostMapping(value = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "Complete Signup with Realm Provisioning",
            description = "Creates a new Keycloak realm with initial admin user and admin product client. " +
                    "This is a comprehensive signup process that sets up the complete multi-tenant environment."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
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
            return ResponseEntity.badRequest().body("Failed to create realm: " + e.getMessage());
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
            return ResponseEntity.badRequest().build();
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
            return ResponseEntity.badRequest().build();
        }
    }

    // ------------------- PRODUCT -------------------
    @PostMapping(
            value = "{realm}/products",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    @Operation(
            summary = "Create Product with Deployment",
            description = "Creates a new product/client in Keycloak and deploys backend/frontend applications. " +
                    "This endpoint handles complete product provisioning including Docker deployment and GitHub repository setup."
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Product created and deployed successfully",
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
    @Operation(
            summary = "Get All Products/Clients",
            description = "Retrieves a list of all products/clients configured in the specified realm"
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
    public ResponseEntity<List<Map<String, Object>>> getAllClients(
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
    @Operation(
            summary = "Get Product UUID",
            description = "Retrieves the internal UUID of a product/client by its client ID name"
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
                    content = @Content(schema = @Schema(example = "Failed to get client UUID: Product not found"))
            )
    })
    public ResponseEntity<String> getClientUUID(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "Product/Client name", required = true, example = "my-product")
            @PathVariable String clientName) {
        try {
            String masterToken = productService.getMyRealmToken(adminUsername, adminPassword, keycloakClientId, masterRealm)
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
            return ResponseEntity.badRequest().body("Failed to create user: " + e.getMessage());
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
            return ResponseEntity.badRequest().build();
        }
    }

    // ------------------- ROLE -------------------
    @PostMapping("{realm}/clients/{clientName}/roles")
    @Operation(
            summary = "Create Product Roles",
            description = "Creates one or more roles for a specific product/client with optional URIs and HTTP methods for API access control"
    )
    @SecurityRequirement(name = "bearer")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Roles created successfully",
                    content = @Content(schema = @Schema(example = "Roles created successfully for client: my-product"))
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Failed to create roles",
                    content = @Content(schema = @Schema(example = "Failed to create roles: Role already exists"))
            )
    })
    public ResponseEntity<String> createClientRoles(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "Product/Client name", required = true, example = "my-product")
            @PathVariable String clientName,
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
            productService.createProductRoles(realm, clientName, roleRequests, token);
            return ResponseEntity.ok("Roles created successfully for client: " + clientName);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to create roles: " + e.getMessage());
        }
    }

    @GetMapping("{realm}/clients/{clientName}/roles")
    @Operation(
            summary = "Get Product Roles",
            description = "Retrieves all roles configured for a specific product/client"
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
                    content = @Content(schema = @Schema(example = "Failed to fetch client roles: Product not found"))
            )
    })
    public ResponseEntity<?> getClientRoles(
            @Parameter(description = "Keycloak realm name", required = true, example = "my-realm")
            @PathVariable String realm,
            @Parameter(description = "Product/Client name", required = true, example = "my-product")
            @PathVariable String clientName,
            @Parameter(description = "JWT Bearer token", required = true)
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
    @Operation(
            summary = "Update Product Role",
            description = "Updates an existing role's details including name, description, URI, and HTTP method for a product/client"
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
            @Parameter(description = "Product/Client name", required = true, example = "my-product")
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
    @Operation(
            summary = "Delete Product Role",
            description = "Permanently deletes a role from a product/client. This action cannot be undone."
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
            @Parameter(description = "Product/Client name", required = true, example = "my-product")
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
            return ResponseEntity.badRequest().body(e.getMessage());

        } catch (Exception e) {
            log.error("🔥 System error", e);
            return ResponseEntity.status(500)
                    .body("Failed to delete role: " + e.getMessage());
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
            @Parameter(description = "Product/Client name", required = true, example = "my-product")
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
        @Parameter(description = "Product/Client name", required = true, example = "my-product")
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
        return ResponseEntity.status(500).body(e.getMessage());
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
        @Parameter(description = "Product/Client name", required = true, example = "my-product")
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
        return ResponseEntity.status(500).body(e.getMessage());
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
            return ResponseEntity.status(500).body(e.getMessage());
        }
    }


}

