package com.paxaris.identity_service.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.stream.Collectors;

import com.paxaris.identity_service.dto.*;
import com.paxaris.identity_service.service.KeycloakProductService;
import com.paxaris.identity_service.service.ProvisioningService;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.net.HttpURLConnection;
import java.io.IOException;

@Service
@RequiredArgsConstructor
public class KeycloakProductServiceImpl implements KeycloakProductService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakProductServiceImpl.class);

    private final KeycloakConfig config;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final ProvisioningService provisioningService;

    @Value("${project.management.base-url}")
    private String projectManagementBaseUrl;
    @Value("${docker.hub.username}")
    private String dockerHubUsername;

    // This method is now private and used internally to avoid duplication
    private String getMasterToken() {
        log.info("Attempting to get master token from Keycloak...");
        String tokenUrl = config.getBaseUrl() + "/realms/master/protocol/openid-connect/token";

        log.debug("Master token URL: {}", tokenUrl);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", "admin-cli");
        body.add("username", config.getAdminUsername());
        body.add("password", config.getAdminPassword());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, Map.class);
            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                log.error("Failed to get master token. Status code: {}", response.getStatusCode());
                throw new RuntimeException("Failed to get master token");
            }
            log.info("Successfully obtained master token.");
            return (String) response.getBody().get("access_token");
        } catch (HttpClientErrorException.Unauthorized e) {
            log.error(
                    "401 Unauthorized: Keycloak master admin credentials or Product-id is incorrect. Please check your configuration. Username: {}, Client-ID: {}",
                    config.getAdminUsername(), "admin-cli");
            throw new RuntimeException("Authentication failed for master token.", e);
        } catch (Exception e) {
            log.error("Failed to get master token due to an error: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to connect to Keycloak token endpoint.", e);
        }
    }
 @Override
    public String getMasterTokenInternally() {
        return getMasterToken();
    }



    @Override
    public Map<String, Object> getMyRealmToken(String username, String password, String productId, String realm) {
        log.info("🚀 Starting login flow for user '{}' in realm '{}' for product '{}'", username, realm, productId);

        try {
            // 1️⃣ Get admin/master token
            String adminToken = getMasterToken();
            log.info("🔐 Master token retrieved");

            // 2️⃣ Fetch product secret dynamically, skip for admin-cli
            String productSecret = null;
            if (!"admin-cli".equals(productId)) {
                productSecret = getProductSecretFromKeycloak(realm, productId);
                log.info("🔐 Product secret retrieved for product '{}'", productId);
            } else {
                log.info("⚠️ Skipping product secret fetch for 'admin-cli'");
            }

            // 3️⃣ Build token URL
            String tokenUrl = config.getBaseUrl() + "/realms/" + realm + "/protocol/openid-connect/token";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("grant_type", "password");
            formData.add("client_id", productId);
            if (productSecret != null) {
                formData.add("client_secret", productSecret);
            }
            formData.add("username", username);
            formData.add("password", password);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(formData, headers);

            // 4️⃣ Request user access token
            ResponseEntity<String> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, String.class);

            // 5️⃣ Return parsed token JSON
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        } catch (Exception e) {
            log.error("💥 Failed to get realm token for user '{}' in product '{}': {}", username, productId, e.getMessage(), e);
            throw new RuntimeException("Failed to get realm token", e);
        }
    }

    private String getProductSecretFromKeycloak(String realm, String productId) {
        log.info("Fetching product secret for product '{}' in realm '{}'", productId, realm);

        try {
            // Step 1: Get admin token
            String adminToken = getMasterToken();
            log.debug("Admin token retrieved: [HIDDEN]");

            // Step 2: Get product (client) internal ID from Keycloak
            String clientsUrl = config.getBaseUrl() + "/admin/realms/" + realm + "/clients?clientId=" + productId;

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            HttpEntity<Void> request = new HttpEntity<>(headers);

            ResponseEntity<List<Map<String, Object>>> clientsResponse = restTemplate.exchange(
                    clientsUrl,
                    HttpMethod.GET,
                    request,
                    new ParameterizedTypeReference<>() {}
            );

            List<Map<String, Object>> products = clientsResponse.getBody();
            if (products == null || products.isEmpty()) {
                throw new RuntimeException("Product not found in Keycloak for productId: " + productId);
            }

            String internalProductId = (String) products.get(0).get("id");
            log.info("Found internal product ID: {}", internalProductId);

            // Step 3: Get the secret for this product (client in Keycloak)
            String secretUrl = config.getBaseUrl() + "/admin/realms/" + realm +
                    "/clients/" + internalProductId + "/client-secret";

            ResponseEntity<Map<String, Object>> secretResponse = restTemplate.exchange(
                    secretUrl,
                    HttpMethod.GET,
                    request,
                    new ParameterizedTypeReference<>() {}
            );

            Map<String, Object> secretBody = secretResponse.getBody();
            if (secretBody == null || secretBody.get("value") == null) {
                throw new RuntimeException("Product secret not found for productId: " + productId);
            }

            String productSecret = (String) secretBody.get("value");
            log.info("Successfully fetched product secret for '{}'", productId);

            return productSecret;

        } catch (Exception e) {
            log.error("Failed to fetch product secret for '{}': {}", productId, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch product secret for product " + productId, e);
        }
    }


    @Override
    public boolean validateToken(String realm, String token) {
        log.info("Attempting to validate token for realm '{}'", realm);
        try {
            String userInfoUrl = config.getBaseUrl() + "/realms/" + realm + "/protocol/openid-connect/userinfo";
            log.debug("User info validation URL: {}", userInfoUrl);
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            ResponseEntity<Map> response = restTemplate.exchange(
                    userInfoUrl, HttpMethod.GET, new HttpEntity<>(headers), Map.class);
            boolean isValid = response.getStatusCode().is2xxSuccessful() && response.getBody() != null;
            if (isValid) {
                log.info("Token for realm '{}' is valid.", realm);
            } else {
                log.warn("Token for realm '{}' is invalid. Status code: {}", realm, response.getStatusCode());
            }
            return isValid;
        } catch (Exception e) {
            log.error("Token validation failed for realm '{}': {}", realm, e.getMessage());
            return false;
        }
    }

    // ---------------- REALM ----------------
    @Override
    public void createRealm(String realmName, String token) {
        log.info("Attempting to create realm: {}", realmName);

        // Check if realm already exists
        if (realmExists(realmName, token)) {
            log.warn("Realm '{}' already exists, skipping creation", realmName);
            return;
        }

        String url = config.getBaseUrl() + "/admin/realms";
        log.debug("Create realm URL: {}", url);
        Map<String, Object> body = Map.of("realm", realmName, "enabled", true);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);

        try {
            restTemplate.postForEntity(url, new HttpEntity<>(body, headers), String.class);
            log.info("Realm '{}' created successfully.", realmName);
        } catch (HttpClientErrorException e) {
            // Check if error is because realm already exists
            if (e.getStatusCode().value() == 400 && e.getResponseBodyAsString() != null
                    && e.getResponseBodyAsString().contains("already exists")) {
                log.warn("Realm '{}' already exists (detected from error response), skipping creation", realmName);
                return;
            }
            log.error("Failed to create realm '{}': {}", realmName, e.getMessage(), e);
            throw new RuntimeException("Failed to create realm: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Failed to create realm '{}': {}", realmName, e.getMessage(), e);
            throw new RuntimeException("Failed to create realm: " + e.getMessage(), e);
        }
    }

    /**
     * Check if a realm exists in Keycloak
     */
    private boolean realmExists(String realmName, String token) {
        try {
            String url = config.getBaseUrl() + "/admin/realms/" + realmName;
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            return response.getStatusCode().is2xxSuccessful();
        } catch (Exception e) {
            log.debug("Realm '{}' does not exist or is not accessible: {}", realmName, e.getMessage());
            return false;
        }
    }

    @Override
    public List<Map<String, Object>> getAllRealms(String token) {
        log.info("Attempting to fetch all realms...");
        String url = config.getBaseUrl() + "/admin/realms";
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            log.info("Successfully fetched all realms.");
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {
            });
        } catch (Exception e) {
            log.error("Failed to fetch realms: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to fetch realms", e);
        }
    }

    // ---------------- CLIENT ----------------
    @Override
    public String createProduct(String realm, String productName, boolean isPublicProduct, String token) {
        log.info("Creating product '{}' in realm '{}'", productName, realm);

        // Keycloak admin endpoint (clients are still Keycloak clients)
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients";

        // Build product (Keycloak client) representation
        Map<String, Object> body = new HashMap<>();
        body.put("clientId", productName); // Keycloak field name must remain clientId
        body.put("enabled", true);
        body.put("protocol", "openid-connect");
        body.put("publicClient", isPublicProduct);
        body.put("standardFlowEnabled", true);
        body.put("directAccessGrantsEnabled", true);
        body.put("authorizationServicesEnabled", true);

        if (isPublicProduct) {
            body.put("clientAuthenticatorType", "client-id");
            body.put("redirectUris", Collections.singletonList("*"));
            body.put("serviceAccountsEnabled", false);
        } else {
            body.put("clientAuthenticatorType", "client-secret");
            body.put("serviceAccountsEnabled", true);
        }

        // Set headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

        // Call Keycloak to create the product
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to create product with status code: " + response.getStatusCode());
        }

        log.info("Product '{}' created successfully in realm '{}'", productName, realm);

        // Retrieve and return the UUID assigned by Keycloak
        return getProductUUID(realm, productName, token);
    }


    @Override
    public List<Map<String, Object>> getAllProducts(String realm, String token) {
        log.info("Attempting to fetch all products for realm '{}'", realm);

        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class
            );

            log.info("Successfully fetched all products for realm '{}'", realm);

            // Deserialize JSON response into a list of maps
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        } catch (Exception e) {
            log.error("Failed to fetch products for realm '{}': {}", realm, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch products", e);
        }
    }



    @Override
    public String getProductUUID(String realm, String productName, String token) {
        log.info("Attempting to get UUID for product '{}' in realm '{}'", productName, realm);

        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients?clientId=" + productName;

        // Ensure token is valid for the realm
        if (token == null || !validateToken(realm, token)) {
            token = getMasterToken();
            log.info("Master token retrieved for realm '{}'", realm);
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                new ParameterizedTypeReference<>() {}
        );

        if (response.getBody() != null && !response.getBody().isEmpty()) {
            String productUUID = (String) response.getBody().get(0).get("id");
            log.info("Found UUID for product '{}': {}", productName, productUUID);
            return productUUID;
        }

        log.error("Product not found in realm '{}': {}", realm, productName);
        throw new RuntimeException("Product not found: " + productName);
    }



    @Override
    public String getProductId(String realm, String productName, String token) {
        log.info("Attempting to get product ID for name '{}'", productName);
        return getProductUUID(realm, productName, token);
    }


    // ---------------- USER5 ----------------
    @Override
    public String createUser(String realm, String token, Map<String, Object> userPayload) {
        String username = (String) userPayload.get("username");
        log.info("Attempting to create user '{}' in realm '{}'", username, realm);
        userPayload.put("emailVerified", true);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/users";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token); // <-- use provided token

        try {
            ResponseEntity<Void> response = restTemplate.postForEntity(url, new HttpEntity<>(userPayload, headers),
                    Void.class);

            if (response.getStatusCode() == HttpStatus.CREATED) {
                String location = response.getHeaders().getFirst("Location");
                if (location != null) {
                    String userId = location.substring(location.lastIndexOf("/") + 1);
                    log.info("User '{}' created successfully with ID: {}", username, userId);
                    return userId;
                }
            }

            log.error("Failed to create user '{}' with status: {}", username, response.getStatusCode());
            throw new RuntimeException("Failed to create user with status: " + response.getStatusCode());

        } catch (Exception e) {
            log.error("Failed to create user '{}': {}", username, e.getMessage(), e);
            throw new RuntimeException("Failed to create user", e);
        }
    }

    @Override
    public List<Map<String, Object>> getAllUsers(String realm, String token) {
        log.info("Attempting to fetch all users for realm '{}'", realm);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/users";
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers),
                    String.class);
            log.info("Successfully fetched all users for realm '{}'.", realm);
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {
            });
        } catch (Exception e) {
            log.error("Failed to fetch users for realm '{}': {}", realm, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch users", e);
        }
    }

    // ---------------- ROLE ----------------
    @Override
    public void createProductRoles(String realm, String productName, List<RoleCreationRequest> roleRequests,
                                   String token) {
        log.info("Attempting to create {} product roles for product '{}' in realm '{}'",
                roleRequests.size(), productName, realm);

        String productUUID = getProductUUID(realm, productName, token);
        log.info("Product UUID for '{}' is '{}'", productName, productUUID);

        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients/" + productUUID + "/roles";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        List<String> failedRoles = new ArrayList<>();

        WebClient webClient = null;
        if (projectManagementBaseUrl != null && !projectManagementBaseUrl.isEmpty()) {
            webClient = WebClient.builder()
                    .baseUrl(projectManagementBaseUrl)
                    .build();
        } else {
            log.warn("Project Management Base URL is not configured, skipping project manager update");
        }

        for (RoleCreationRequest role : roleRequests) {
            Map<String, Object> body = Map.of(
                    "name", role.getName(),
                    "description", role.getDescription());
            try {
                restTemplate.postForEntity(url, new HttpEntity<>(body, headers), String.class);
                log.info("Role '{}' created successfully.", role.getName());

                // Send to Project Management Service if configured
                if (webClient != null) {
                    RoleRequest roleRequest = new RoleRequest();
                    roleRequest.setRealmName(realm);
                    roleRequest.setProductName(productName);
                    roleRequest.setRoleName(role.getName());

                    UrlEntry urlEntry = new UrlEntry();
                    urlEntry.setUrl(role.getUrl());
                    urlEntry.setUri(role.getUri());

                    roleRequest.setUrls(List.of(urlEntry));

                    try {
                        webClient.post()
                                .uri("/project/roles/save-or-update")
                                .bodyValue(roleRequest)
                                .retrieve()
                                .toBodilessEntity()
                                .block();
                        log.info("Project Management Service updated for role '{}'", role.getName());
                    } catch (Exception e) {
                        log.error("Failed to update Project Management Service for role '{}': {}", role.getName(),
                                e.getMessage());
                        // Optionally add role name to failedRoles or handle separately
                    }
                }

            } catch (Exception e) {
                failedRoles.add(role.getName());
                log.error("Failed to create role '{}': {}", role.getName(), e.getMessage());
            }
        }

        if (!failedRoles.isEmpty()) {
            throw new RuntimeException("Failed to create roles: " + String.join(", ", failedRoles));
        }
    }


    // -------------------------------getProductRoles----------------------------------
    @Override
    public List<Map<String, Object>> getProductRoles(String realm, String productName, String token) {
        log.info("Fetching roles for product '{}' in realm '{}'", productName, realm);

        // Get the product UUID
        String productUUID = getProductUUID(realm, productName, token);
        log.info("Product UUID for '{}' is '{}'", productName, productUUID);

        // Keycloak endpoint for roles under a product
        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/clients/" + productUUID
                + "/roles";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Void> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<List> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    entity,
                    List.class
            );

            log.info("Successfully fetched roles for product '{}'", productName);
            return response.getBody();

        } catch (Exception e) {
            log.error("Failed to fetch roles for product '{}': {}", productName, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch product roles", e);
        }
    }



    @Override
    public boolean updateRole(String realm, String productUUID, String roleName, RoleCreationRequest role, String token) {
        log.info("Attempting to update product role '{}' for product UUID '{}' in realm '{}'", roleName, productUUID, realm);

        try {
            String url = config.getBaseUrl() + "/admin/realms/" + realm
                    + "/clients/" + productUUID
                    + "/roles/" + roleName;

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, Object> body = Map.of(
                    "name", role.getName(),
                    "description", role.getDescription()
            );

            restTemplate.put(url, new HttpEntity<>(body, headers));

            log.info("Product role '{}' updated successfully.", roleName);
            return true;

        } catch (Exception e) {
            log.error("Failed to update product role '{}': {}", roleName, e.getMessage(), e);
            return false;
        }
    }

    @Override
    public boolean deleteProductRole(String realm, String productUUID, String roleName, String token) {
        log.info("Attempting to delete role '{}' for product with UUID '{}' in realm '{}'", roleName, productUUID, realm);

        try {
            // Keycloak endpoint for deleting a role under a product
            String url = config.getBaseUrl()
                    + "/admin/realms/" + realm
                    + "/clients/" + productUUID
                    + "/roles/" + roleName;

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);

            restTemplate.exchange(url, HttpMethod.DELETE, new HttpEntity<>(headers), String.class);
            log.info("Role '{}' deleted successfully for product '{}'.", roleName, productUUID);
            return true;

        } catch (Exception e) {
            log.error("Failed to delete role '{}' for product '{}': {}", roleName, productUUID, e.getMessage(), e);
            return false;
        }
    }

    // ---------------- ROLE ASSIGN ----------------
    @Override
    public void assignProductRolesByName(
            String realm,
            String username,
            String productName,
            String token,
            List<AssignRoleRequest> roles) {

        // 1️⃣ Resolve userId from username
        String userId = resolveUserId(realm, username, token);

        // 2️⃣ Resolve product UUID from productName (Keycloak client UUID)
        String productUUID = resolveProductUUID(realm, productName, token);

        // 3️⃣ Resolve each role by name → minimal payload (id + name)
        List<Map<String, Object>> resolvedRoles = new ArrayList<>();

        for (AssignRoleRequest role : roles) {
            if (role.getName() == null || role.getName().isBlank()) {
                throw new IllegalArgumentException("Role name must not be null or empty");
            }

            Map<String, Object> resolvedRole =
                    resolveProductRoleByName(realm, productUUID, role.getName(), token);

            resolvedRoles.add(resolvedRole);
        }

        // 4️⃣ Assign resolved product roles to user
        assignProductRolesToUser(realm, userId, productUUID, resolvedRoles, token);

        // 5️⃣ Log cURL command for debugging
        logCurlCommand(realm, userId, productUUID, resolvedRoles, token);

        log.info(
                "✅ Successfully assigned product roles {} to user '{}' in realm '{}' for product '{}'",
                resolvedRoles.stream().map(r -> r.get("name")).toList(),
                username,
                realm,
                productName);
    }

    private void logCurlCommand(String realm, String userId, String productUUID,
                                List<Map<String, Object>> roles, String token) {

        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/users/" + userId
                + "/role-mappings/clients/" + productUUID;

        String rolesJson;
        try {
            rolesJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(roles);
        } catch (Exception e) {
            rolesJson = roles.toString();
        }

        String curl = "curl --location '" + url + "' \\\n"
                + "  --header 'Content-Type: application/json' \\\n"
                + "  --header 'Authorization: Bearer " + token + "' \\\n"
                + "  --data-raw '" + rolesJson.replace("'", "\\'") + "'";

        log.info("🔹 Equivalent cURL command to assign product roles:\n{}", curl);
    }

    private String resolveProductUUID(String realm, String productName, String token) {
        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/clients?clientId=" + productName; // clientId is still Keycloak field

        HttpHeaders headers = authHeaders(token);

        ResponseEntity<List> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers), List.class);

        List<Map<String, Object>> products = response.getBody();

        if (products == null || products.isEmpty()) {
            throw new RuntimeException("Product not found: " + productName);
        }

        return products.get(0).get("id").toString(); // Keycloak internal UUID
    }


    private Map<String, Object> resolveProductRoleByName(
            String realm,
            String productUUID,
            String roleName,
            String token) {

        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/clients/" + productUUID   // still client internally
                + "/roles/" + roleName;

        HttpHeaders headers = authHeaders(token);

        ResponseEntity<Map> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers), Map.class);

        Map<String, Object> role = response.getBody();

        if (role == null) {
            throw new RuntimeException("Product role not found: " + roleName);
        }

        // 🔥 Minimal payload required by Keycloak
        Map<String, Object> minimalRole = new HashMap<>();
        minimalRole.put("id", role.get("id"));
        minimalRole.put("name", role.get("name"));

        return minimalRole;
    }


    private void assignProductRolesToUser(
            String realm,
            String userId,
            String productUUID,
            List<Map<String, Object>> roles,
            String token) {

        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/users/" + userId
                + "/role-mappings/clients/" + productUUID; // still clients internally

        HttpHeaders headers = authHeaders(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<List<Map<String, Object>>> request = new HttpEntity<>(roles, headers);

        restTemplate.postForEntity(url, request, Void.class);

        log.info("Assigned product roles {} to user {}", roles, userId);
    }

    private HttpHeaders authHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }

    // ---------------- SIGNUP ----------------
    @Override
    public SignupStatus signup(SignupRequest request, MultipartFile sourceZip) {
        // Validate required inputs first
        if (request == null) {
            throw new IllegalArgumentException("SignupRequest cannot be null");
        }

        SignupStatus status = SignupStatus.builder()
                .status("IN_PROGRESS")
                .message("Signup process started")
                .steps(new ArrayList<>())
                .build();

        log.info("🚀 Starting comprehensive signup process for product '{}', realm '{}'",
                request.getProductName(), request.getRealmName());

        if (sourceZip == null || sourceZip.isEmpty()) {
            throw new IllegalArgumentException("Source ZIP file is required");
        }
        if (request.getAdminUser() == null) {
            throw new IllegalArgumentException("Admin user information is required");
        }

        String masterToken = null;
        String realm = request.getRealmName() != null ? request.getRealmName() : "default-realm";
        String productName = request.getProductName() != null ? request.getProductName() : "default-product";
        String adminUsername = request.getAdminUser().getUsername() != null ? request.getAdminUser().getUsername() : "admin";
        Path extractedCodePath = null;

        try {
            // Step 1: Get Master Token
            status.addStep("Get Master Token", "IN_PROGRESS", "Authenticating with Keycloak master realm");
            log.info("🔐 Step 1: Getting master token");
            masterToken = getMasterToken();
            status.addStep("Get Master Token", "SUCCESS", "Master token retrieved successfully");

            // Step 2: Create Realm
            status.addStep("Create Realm", "IN_PROGRESS", "Creating Keycloak realm: " + realm);
            log.info("🧱 Step 2: Creating realm '{}'", realm);
            createRealm(realm, masterToken);
            status.addStep("Create Realm", "SUCCESS", "Realm '" + realm + "' created successfully");

            // Step 3: Create Product (was Client)
            status.addStep("Create Product", "IN_PROGRESS", "Creating Keycloak product: " + productName);
            log.info("🧩 Step 3: Creating product '{}'", productName);
            String productUUID = createProduct(realm, productName, request.isPublicClient(), masterToken);
            status.addStep("Create Product", "SUCCESS",
                    "Product '" + productName + "' created successfully with UUID: " + productUUID);

            // Step 4: Create Admin User
            status.addStep("Create Admin User", "IN_PROGRESS", "Creating admin user: " + adminUsername);
            log.info("👤 Step 4: Creating admin user '{}'", adminUsername);

            Map<String, Object> userMap = new HashMap<>();
            userMap.put("username", adminUsername);
            userMap.put("email", request.getAdminUser().getEmail());
            userMap.put("firstName", request.getAdminUser().getFirstName());
            userMap.put("lastName", request.getAdminUser().getLastName());
            userMap.put("enabled", true);

            Map<String, Object> credentials = Map.of(
                    "type", "password",
                    "value", request.getAdminUser().getPassword(),
                    "temporary", false
            );
            userMap.put("credentials", List.of(credentials));

            String userId = createUser(realm, masterToken, userMap);
            status.addStep("Create Admin User", "SUCCESS", "Admin user '" + adminUsername + "' created successfully");

            // Step 5: Assign default roles
            status.addStep("Assign Admin Roles", "IN_PROGRESS", "Assigning default admin roles");
            log.info("🔑 Step 5: Assigning default admin roles to '{}'", adminUsername);
            List<String> defaultRoles = List.of("create-product", "impersonation", "manage-realm", "manage-users", "manage-products");
            for (String role : defaultRoles) {
                assignRealmManagementRoleToUser(realm, userId, role, masterToken);
            }
            status.addStep("Assign Admin Roles", "SUCCESS", "Default admin roles assigned successfully");

            // Step 6: Send data to Project Management Service
            status.addStep("Update Project Manager", "IN_PROGRESS",
                    "Sending project info to Project Management Service");
            log.info("📤 Step 6: Sending project info to Project Management Service...");

            UrlEntry urlEntry = new UrlEntry();
            urlEntry.setUrl(request.getUrl());
            urlEntry.setUri(request.getUri());

            RoleRequest roleRequest = new RoleRequest();
            roleRequest.setRealmName(realm);
            roleRequest.setProductName(productName);
            roleRequest.setRoleName("admin");
            roleRequest.setUrls(List.of(urlEntry));

            if (projectManagementBaseUrl == null || projectManagementBaseUrl.isEmpty()) {
                log.warn("Project Management Base URL is not configured, skipping project manager update");
                status.addStep("Update Project Manager", "SKIPPED", "Project Management Base URL not configured");
            } else {
                WebClient webClient = WebClient.builder()
                        .baseUrl(projectManagementBaseUrl)
                        .build();

                webClient.post()
                        .uri("/project/roles/save-or-update")
                        .bodyValue(roleRequest)
                        .retrieve()
                        .toBodilessEntity()
                        .block();

                status.addStep("Update Project Manager", "SUCCESS", "Project info sent to Project Management Service");
            }

            // Step 7: Extract ZIP file
            status.addStep("Extract Application Code", "IN_PROGRESS", "Extracting uploaded ZIP file");
            log.info("📦 Step 7: Extracting application code from ZIP file");
            extractedCodePath = Files.createTempDirectory("signup-extract-" + System.currentTimeMillis());
            extractZipFile(sourceZip, extractedCodePath);
            status.addStep("Extract Application Code", "SUCCESS", "Application code extracted successfully");

            // Step 8: Generate repository name using realm, admin username, and product name
            String repoName = ProvisioningService.generateRepositoryName(realm, adminUsername, productName);
            status.addStep("Generate Repository Name", "SUCCESS", "Repository name generated: " + repoName);
            log.info("📝 Step 8: Generated repository name: {}", repoName);

            // Step 9: Create GitHub Repository
            status.addStep("Create GitHub Repository", "IN_PROGRESS", "Creating GitHub repository: " + repoName);
            log.info("🐙 Step 9: Creating GitHub repository '{}'", repoName);
            provisioningService.createRepo(repoName);
            status.addStep("Create GitHub Repository", "SUCCESS",
                    "GitHub repository '" + repoName + "' created successfully");

            // Step 10: Upload code to GitHub
            status.addStep("Upload Code to GitHub", "IN_PROGRESS", "Uploading application code to GitHub");
            log.info("⬆️ Step 10: Uploading code to GitHub repository");
            uploadDirectoryToGitHub(extractedCodePath, repoName);
            status.addStep("Upload Code to GitHub", "SUCCESS", "Code uploaded to GitHub successfully");

            // Cleanup extracted code
            if (extractedCodePath != null && Files.exists(extractedCodePath)) {
                try {
                    Files.walk(extractedCodePath)
                            .sorted(java.util.Comparator.reverseOrder())
                            .forEach(path -> {
                                try {
                                    Files.delete(path);
                                } catch (Exception ignored) {
                                }
                            });
                } catch (Exception e) {
                    log.warn("Failed to cleanup extracted code directory: {}", e.getMessage());
                }
            }

            status.setStatus("SUCCESS");
            status.setMessage("Signup process completed successfully");
            log.info("🎉 Signup process completed successfully for realm '{}'", realm);

            return status;

        } catch (Exception e) {
            log.error("💥 Signup process failed: {}", e.getMessage(), e);
            status.setStatus("FAILED");
            status.setMessage("Signup process failed: " + e.getMessage());

            // Mark the last in-progress step as failed
            if (!status.getSteps().isEmpty()) {
                SignupStatus.StepStatus lastStep = status.getSteps().get(status.getSteps().size() - 1);
                if ("IN_PROGRESS".equals(lastStep.getStatus())) {
                    lastStep.setStatus("FAILED");
                    lastStep.setError(e.getMessage());
                }
            }

            // Cleanup on failure
            if (extractedCodePath != null && Files.exists(extractedCodePath)) {
                try {
                    Files.walk(extractedCodePath)
                            .sorted(java.util.Comparator.reverseOrder())
                            .forEach(path -> {
                                try {
                                    Files.delete(path);
                                } catch (Exception ignored) {
                                }
                            });
                } catch (Exception cleanupEx) {
                    log.warn("Failed to cleanup extracted code directory: {}", cleanupEx.getMessage());
                }
            }

            throw new RuntimeException("Signup failed: " + e.getMessage(), e);
        }
    }


    private void extractZipFile(MultipartFile zipFile, Path extractPath) throws IOException {
        try {
            // Try using Apache Commons Compress first (handles more ZIP formats)
            org.apache.commons.compress.archivers.zip.ZipArchiveInputStream zis = new org.apache.commons.compress.archivers.zip.ZipArchiveInputStream(
                    zipFile.getInputStream());

            org.apache.commons.compress.archivers.ArchiveEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path resolvedPath = extractPath.resolve(entry.getName()).normalize();
                if (!resolvedPath.startsWith(extractPath)) {
                    throw new IOException("Invalid zip entry: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(resolvedPath);
                } else {
                    Files.createDirectories(resolvedPath.getParent());
                    Files.copy(zis, resolvedPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
            zis.close();
        } catch (Exception e) {
            log.warn("Apache Commons Compress extraction failed, trying standard ZipInputStream: {}", e.getMessage());
            // Fallback to standard ZipInputStream
            try (java.util.zip.ZipInputStream zis = new java.util.zip.ZipInputStream(zipFile.getInputStream())) {
                java.util.zip.ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    Path resolvedPath = extractPath.resolve(entry.getName()).normalize();
                    if (!resolvedPath.startsWith(extractPath)) {
                        throw new IOException("Invalid zip entry: " + entry.getName());
                    }
                    if (entry.isDirectory()) {
                        Files.createDirectories(resolvedPath);
                    } else {
                        Files.createDirectories(resolvedPath.getParent());
                        Files.copy(zis, resolvedPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    }
                    zis.closeEntry();
                }
            } catch (Exception fallbackException) {
                log.error("Both ZIP extraction methods failed. Original: {}, Fallback: {}",
                        e.getMessage(), fallbackException.getMessage());
                throw new IOException(
                        "Failed to extract ZIP file. The ZIP file may be corrupted or use an unsupported format. " +
                                "Please ensure the ZIP file is valid and uses standard DEFLATE compression.",
                        fallbackException);
            }
        }
    }


    private void uploadDirectoryToGitHub(Path root, String repo) throws Exception {
        java.nio.file.Files.walk(root)
                .filter(java.nio.file.Files::isRegularFile)
                .forEach(file -> {
                    try {
                        uploadFileToGitHub(root, file, repo);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    private void uploadFileToGitHub(Path root, Path file, String repo) throws Exception {
        String path = root.relativize(file).toString().replace("\\", "/");
        byte[] content = java.nio.file.Files.readAllBytes(file);
        String base64 = Base64.getEncoder().encodeToString(content);

        String api = "https://api.github.com/repos/" + provisioningService.getGithubOrg() + "/" + repo + "/contents/"
                + path;

        HttpURLConnection conn = (HttpURLConnection) new java.net.URL(api).openConnection();
        conn.setRequestMethod("PUT");
        conn.setRequestProperty("Authorization", "Bearer " + provisioningService.getGithubToken());
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        String payload = String.format("""
                {
                  "message": "initial commit",
                  "content": "%s"
                }
                """, base64);

        conn.getOutputStream().write(payload.getBytes());

        if (conn.getResponseCode() >= 300) {
            throw new RuntimeException("File upload failed: " + path);
        }
    }

private String resolveUserId(String realm, String username, String token) {
    log.info("Resolving user ID for username '{}' in realm '{}'", username, realm);
    String url = config.getBaseUrl() + "/admin/realms/" + realm + "/users?username=" + username;
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);

    try {
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers),
                String.class);
        List<Map<String, Object>> users = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        log.info("Users returned from Keycloak for username query '{}': {}", username, users);

        // Filter for exact username match, case-insensitive
        List<Map<String, Object>> exactMatches = users.stream()
            .filter(u -> username.equalsIgnoreCase((String) u.get("username")))
            .collect(Collectors.toList());

        if (exactMatches.isEmpty()) {
            log.error("No exact match found for username '{}'", username);
            throw new RuntimeException("User not found with exact username: " + username);
        }

        if (exactMatches.size() > 1) {
            log.warn("Multiple exact matches found for username '{}', picking the first", username);
        }

        String userId = (String) exactMatches.get(0).get("id");
        log.info("Resolved exact user ID: '{}' for username '{}'", userId, username);
        return userId;
    } catch (Exception e) {
        log.error("Failed to resolve user UUID for '{}': {}", username, e.getMessage(), e);
        throw new RuntimeException("Failed to resolve user UUID for: " + username, e);
    }
}


    private String getProductRoleId(String realm, String productUUID, String roleName, String token) {
        log.info("Fetching product role ID for role '{}' on product UUID '{}'", roleName, productUUID);


        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/clients/" + productUUID
                + "/roles/" + roleName;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    new ParameterizedTypeReference<>() {}
            );

            Map<String, Object> role = response.getBody();

            if (role == null || role.get("id") == null) {
                throw new RuntimeException("Product role not found: " + roleName);
            }

            String roleId = (String) role.get("id");
            log.info("Fetched product role ID '{}' for role name '{}'", roleId, roleName);
            return roleId;

        } catch (Exception e) {
            log.error("Failed to fetch product role ID for product UUID '{}': {}", productUUID, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch product role ID", e);
        }
    }


    private void assignRealmManagementRoleToUser(String realm, String userId, String roleName, String token) {
        log.info("Assigning realm management role '{}' to user ID '{}'", roleName, userId);
        String productId = getRealmManagementProductId(realm, token);
        String roleId = getRealmManagementRoleId(realm, roleName, token);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/clients/"
                + productId;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        List<Map<String, Object>> roles = List.of(Map.of("id", roleId, "name", roleName));

        try {
            restTemplate.postForEntity(url, new HttpEntity<>(roles, headers), String.class);
            log.info("Realm management role '{}' assigned successfully to user ID '{}'", roleName, userId);
        } catch (Exception e) {
            log.error("Failed to assign realm role '{}' to user ID '{}': {}", roleName, userId, e.getMessage(), e);
            throw new RuntimeException("Failed to assign realm role to user: " + e.getMessage(), e);
        }
    }

    private String getRealmManagementProductId(String realm, String token) {
        log.info("Fetching realm-management product ID for realm '{}'", realm);

        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/clients?clientId=realm-management";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                new ParameterizedTypeReference<>() {}
        );

        if (response.getBody() != null && !response.getBody().isEmpty()) {
            String productId = (String) response.getBody().get(0).get("id");
            log.info("Found realm-management product ID: {}", productId);
            return productId;
        }

        log.error("realm-management product not found in realm '{}'.", realm);
        throw new RuntimeException("realm-management product not found");
    }


    private String getRealmManagementRoleId(String realm, String roleName, String token) {
        log.info("Fetching realm management role ID for role '{}'", roleName);

        String productId = getRealmManagementProductId(realm, token);


        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/clients/" + productId
                + "/roles/" + roleName;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    new ParameterizedTypeReference<>() {}
            );

            Map<String, Object> role = response.getBody();
            if (role == null || role.get("id") == null) {
                throw new RuntimeException("Role not found: " + roleName);
            }

            String roleId = (String) role.get("id");
            log.info("Found realm management role ID: {}", roleId);
            return roleId;

        } catch (Exception e) {
            log.error("Failed to fetch realm management role ID for '{}': {}", roleName, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch role ID: " + roleName, e);
        }
    }

}
