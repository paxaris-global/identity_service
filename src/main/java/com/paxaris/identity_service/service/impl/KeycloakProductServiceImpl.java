package com.paxaris.identity_service.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.paxaris.identity_service.dto.*;
import com.paxaris.identity_service.service.KeycloakProductService;
import com.paxaris.identity_service.service.ProvisioningService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * KeycloakProductService Implementation - Modular, Best-Practice Design
 *
 * Comprehensive Keycloak integration service with clear separation of concerns:
 * - Token Management: Master realm and user realm authentication
 * - Realm Operations: CRUD operations for Keycloak realms
 * - Product Management: Client/product creation with GitHub provisioning
 * - User Management: User CRUD and resolution
 * - Role Management: Role creation, assignment, and authorization
 * - Signup Workflow: Complete onboarding orchestration
 * - HTTP Helpers: Standardized request/response handling
 * - File Operations: ZIP extraction and GitHub uploads
 *
 * Architecture: Modular design with private helper methods grouped by functional area.
 * All Keycloak URLs built through centralized buildUrl() method.
 * All HTTP requests standardized with reusable helper methods.
 * Comprehensive logging with DEBUG level details for troubleshooting.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakProductServiceImpl implements KeycloakProductService {

    private static final String ADMIN_CLI_CLIENT = "admin-cli";
    private static final String MASTER_REALM = "master";
    private static final String GRANT_TYPE_PASSWORD = "password";
    private static final String REALM_MANAGEMENT_CLIENT = "realm-management";
    private static final String PROTOCOL_OPENID_CONNECT = "openid-connect";
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_EMAIL = "admin@paxarisglobal.com";
    private static final int TOKEN_LIFESPAN_SECONDS = 7200;
    private static final int SSO_SESSION_IDLE_TIMEOUT = 28800;
    private static final int SSO_SESSION_MAX_LIFESPAN = 86400;

    private final KeycloakConfig config;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final ProvisioningService provisioningService;
    private final WebClient webClient;

    @Value("${project.management.base-url}")
    private String projectManagementBaseUrl;


    // ==================== TOKEN MANAGEMENT ====================

    private String getMasterToken() {
        log.debug("Fetching master admin token from Keycloak");
        String tokenUrl = buildUrl("/realms/" + MASTER_REALM + "/protocol/openid-connect/token");
        MultiValueMap<String, String> body = buildTokenRequestBody(
            GRANT_TYPE_PASSWORD, ADMIN_CLI_CLIENT, config.getAdminUsername(), config.getAdminPassword(), null);

        try {
            Map<String, Object> response = executeTokenRequest(tokenUrl, body);
            String token = (String) response.get("access_token");
            log.debug("Master token retrieved successfully");
            return token;
        } catch (HttpClientErrorException.Unauthorized e) {
            log.error("Master token auth failed - Username: {}, Client: {}. Check Keycloak credentials.",
                config.getAdminUsername(), ADMIN_CLI_CLIENT);
            throw new RuntimeException("Authentication failed for master token", e);
        } catch (Exception e) {
            log.error("Failed to fetch master token from Keycloak: {}", e.getMessage());
            throw new RuntimeException("Failed to connect to Keycloak", e);
        }
    }

    @Override
    public String getMasterTokenInternally() {
        return getMasterToken();
    }

    @Override
    public Map<String, Object> getRealmToken(String realm, String username, String password,
                                              String clientId, String clientSecret) {
        log.debug("Authenticating user '{}' in realm '{}'", username, realm);
        String tokenUrl = buildUrl("/realms/" + realm + "/protocol/openid-connect/token");
        MultiValueMap<String, String> body = buildTokenRequestBody(GRANT_TYPE_PASSWORD, clientId, username, password, clientSecret);

        try {
            return executeTokenRequest(tokenUrl, body);
        } catch (HttpClientErrorException e) {
            log.error("Login failed for user '{}' in realm '{}': {}", username, realm, e.getResponseBodyAsString());
            throw new RuntimeException("Login failed: " + e.getResponseBodyAsString(), e);
        }
    }

    @Override
    public Map<String, Object> getMyRealmToken(String username, String password, String clientId, String realm) {
        log.debug("Starting login flow for user '{}' in realm '{}' with client '{}'", username, realm, clientId);

        try {
            String clientSecret = null;
            if (!ADMIN_CLI_CLIENT.equals(clientId)) {
                clientSecret = fetchProductSecretByClientId(realm, clientId);
                log.debug("Client secret resolved for client '{}'", clientId);
            }

            String tokenUrl = buildUrl("/realms/" + realm + "/protocol/openid-connect/token");
            MultiValueMap<String, String> formData = buildTokenRequestBody(GRANT_TYPE_PASSWORD, clientId, username, password, clientSecret);

            HttpHeaders headers = createFormHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(formData, headers);

            ResponseEntity<String> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, String.class);
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        } catch (Exception e) {
            log.error("Failed to get realm token for user '{}': {}", username, e.getMessage());
            throw new RuntimeException("Failed to get realm token", e);
        }
    }

    @Override
    public boolean validateToken(String realm, String token) {
        log.debug("Validating token for realm '{}'", realm);
        try {
            String userInfoUrl = buildUrl("/realms/" + realm + "/protocol/openid-connect/userinfo");
            HttpHeaders headers = createBearerHeaders(token);
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                userInfoUrl, HttpMethod.GET, new HttpEntity<>(headers), new ParameterizedTypeReference<>() {});

            boolean isValid = response.getStatusCode().is2xxSuccessful() && response.getBody() != null;
            log.debug("Token validation for realm '{}': {}", realm, isValid ? "VALID" : "INVALID");
            return isValid;
        } catch (Exception e) {
            log.debug("Token validation failed for realm '{}': {}", realm, e.getMessage());
            return false;
        }
    }

    @Override
    public String getProductRedirectUrl(String realm, String clientId) {
        log.debug("Fetching redirect URL for product '{}' in realm '{}'", clientId, realm);
        try {
            String adminToken = getMasterToken();
            String clientUUID = getProductUUID(realm, clientId, adminToken);
            String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID);
            HttpHeaders headers = createBearerHeaders(adminToken);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers), new ParameterizedTypeReference<>() {});

            Map<String, Object> clientDetails = response.getBody();
            if (clientDetails != null) {
                List<String> redirectUris = (List<String>) clientDetails.get("redirectUris");
                return (redirectUris != null && !redirectUris.isEmpty()) ? redirectUris.get(0) : null;
            }
            return null;
        } catch (Exception e) {
            log.error("Failed to fetch redirect URL for product '{}': {}", clientId, e.getMessage());
            throw new RuntimeException("Failed to fetch redirect URL", e);
        }
    }


    // ==================== REALM MANAGEMENT ====================

    @Override
    public void createRealm(String realmName, String token) {
        log.info("Creating realm '{}'", realmName);
        if (realmExists(realmName, token)) {
            log.warn("Realm '{}' already exists, skipping creation", realmName);
            return;
        }

        String url = buildUrl("/admin/realms");
        Map<String, Object> body = Map.of("realm", realmName, "enabled", true);
        HttpHeaders headers = createJsonHeaders(token);

        try {
            restTemplate.postForEntity(url, new HttpEntity<>(body, headers), String.class);
            log.info("Realm '{}' created successfully", realmName);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode().value() == 400 && e.getResponseBodyAsString().contains("already exists")) {
                log.warn("Realm '{}' already exists", realmName);
                return;
            }
            log.error("Failed to create realm '{}': {}", realmName, e.getMessage());
            throw new RuntimeException("Failed to create realm: " + e.getMessage(), e);
        }
    }

    private boolean realmExists(String realmName, String token) {
        try {
            String url = buildUrl("/admin/realms/" + realmName);
            HttpHeaders headers = createBearerHeaders(token);
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            return response.getStatusCode().is2xxSuccessful();
        } catch (Exception e) {
            log.debug("Realm '{}' does not exist", realmName);
            return false;
        }
    }

    @Override
    public List<Map<String, Object>> getAllRealms(String token) {
        log.info("Fetching all realms");
        String url = buildUrl("/admin/realms");
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        } catch (Exception e) {
            log.error("Failed to fetch realms: {}", e.getMessage());
            throw new RuntimeException("Failed to fetch realms", e);
        }
    }


    // ==================== PRODUCT (CLIENT) MANAGEMENT ====================

    @Override
    public String createProduct(String realm, String clientId, boolean isPublicClient, String adminToken,
            MultipartFile backendZip, MultipartFile frontendZip, String frontendBaseUrl,
            SignupStatus status, String ownerUsername) {

        Path backendPath = null;
        Path frontendPath = null;

        try {
            status.addStep("Create Client", "IN_PROGRESS", "Creating Keycloak client");
            String clientUUID = createKeycloakClient(realm, clientId, isPublicClient, frontendBaseUrl, adminToken);
            status.addStep("Create Client", "SUCCESS", "Client created: " + clientUUID);

            status.addStep("Extract Application Code", "IN_PROGRESS", "Extracting ZIP files");
            backendPath = Files.createTempDirectory("backend-extract-");
            frontendPath = Files.createTempDirectory("frontend-extract-");
            extractZipFile(backendZip, backendPath);
            extractZipFile(frontendZip, frontendPath);
            status.addStep("Extract Application Code", "SUCCESS", "ZIP files extracted");

            String backendRepo = ProvisioningService.generateRepositoryName(realm, ownerUsername, clientId + "-backend");
            String frontendRepo = ProvisioningService.generateRepositoryName(realm, ownerUsername, clientId + "-frontend");
            status.addStep("Generate Repository Names", "SUCCESS", backendRepo + " & " + frontendRepo);

            status.addStep("Create GitHub Repositories", "IN_PROGRESS", "Creating repositories");
            provisioningService.createRepo(backendRepo);
            provisioningService.createRepo(frontendRepo);
            status.addStep("Create GitHub Repositories", "SUCCESS", "Repositories created");

            status.addStep("Upload Code to GitHub", "IN_PROGRESS", "Uploading code");
            uploadDirectoryToGitHub(backendPath, backendRepo);
            uploadDirectoryToGitHub(frontendPath, frontendRepo);
            status.addStep("Upload Code to GitHub", "SUCCESS", "Code uploaded successfully");

            cleanupDirectory(backendPath);
            cleanupDirectory(frontendPath);

            status.setStatus("SUCCESS");
            status.setMessage("Product provisioning completed successfully");
            return clientUUID;

        } catch (Exception e) {
            log.error("Product provisioning failed for realm '{}', product '{}': {}", realm, clientId, e.getMessage());
            handleProvisioningFailure(status, e);
            cleanupDirectory(backendPath);
            cleanupDirectory(frontendPath);
            throw new RuntimeException("Product provisioning failed", e);
        }
    }

    private String createKeycloakClient(String realm, String clientId, boolean isPublicClient,
                                        String frontendBaseUrl, String token) {
        log.info("Creating Keycloak client '{}' in realm '{}' (public={})", clientId, realm, isPublicClient);
        String url = buildUrl("/admin/realms/" + realm + "/clients");
        Map<String, Object> body = buildClientConfiguration(clientId, isPublicClient, frontendBaseUrl);
        HttpHeaders headers = createJsonHeaders(token);

        try {
            restTemplate.exchange(url, HttpMethod.POST, new HttpEntity<>(body, headers), Void.class);
            String clientUUID = getProductUUID(realm, clientId, token);
            if (!isPublicClient) {
                ensureClientSecret(realm, clientUUID, token);
            }
            log.info("Client '{}' created successfully with UUID: {}", clientId, clientUUID);
            return clientUUID;
        } catch (Exception e) {
            log.error("Failed to create client '{}': {}", clientId, e.getMessage());
            throw new RuntimeException("Failed to create client", e);
        }
    }

    private Map<String, Object> buildClientConfiguration(String clientId, boolean isPublicClient, String frontendBaseUrl) {
        Map<String, Object> config = new HashMap<>();
        config.put("clientId", clientId);
        config.put("enabled", true);
        config.put("protocol", PROTOCOL_OPENID_CONNECT);

        if (isPublicClient) {
            config.put("publicClient", true);
            config.put("standardFlowEnabled", true);
            config.put("directAccessGrantsEnabled", false);
            config.put("serviceAccountsEnabled", false);
            config.put("implicitFlowEnabled", false);
            config.put("redirectUris", List.of(frontendBaseUrl + "/*"));
            config.put("webOrigins", List.of(frontendBaseUrl));
            config.put("rootUrl", frontendBaseUrl);
            config.put("baseUrl", frontendBaseUrl);
            config.put("attributes", Map.of("post.logout.redirect.uris", frontendBaseUrl + "/*"));
        } else {
            config.put("publicClient", false);
            config.put("clientAuthenticatorType", "client-secret");
            config.put("serviceAccountsEnabled", true);
            config.put("directAccessGrantsEnabled", false);
            config.put("standardFlowEnabled", false);
            config.put("implicitFlowEnabled", false);
            config.put("bearerOnly", false);
        }
        return config;
    }

    private void ensureClientSecret(String realm, String clientUUID, String token) {
        log.debug("Generating client secret for UUID: {}", clientUUID);
        String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID + "/client-secret");
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url, HttpMethod.POST, new HttpEntity<>(headers), new ParameterizedTypeReference<>() {});
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("Failed to generate client secret");
            }
            log.debug("Client secret generated successfully for UUID: {}", clientUUID);
        } catch (Exception e) {
            log.error("Failed to generate client secret: {}", e.getMessage());
            throw new RuntimeException("Failed to generate client secret", e);
        }
    }

    @Override
    public List<Map<String, Object>> getAllProducts(String realm, String token) {
        log.info("Fetching all products (clients) in realm '{}'", realm);
        String url = buildUrl("/admin/realms/" + realm + "/clients");
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        } catch (Exception e) {
            log.error("Failed to fetch products for realm '{}': {}", realm, e.getMessage());
            throw new RuntimeException("Failed to fetch products", e);
        }
    }

    @Override
    public String getProductSecret(String realm, String clientId, String token) {
        log.debug("Fetching product secret for client '{}' in realm '{}'", clientId, realm);
        String clientUUID = getProductUUID(realm, clientId, token);
        String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID + "/client-secret");
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            Map<String, Object> map = objectMapper.readValue(response.getBody(), new TypeReference<>() {});
            return (String) map.get("value");
        } catch (Exception e) {
            log.error("Failed to fetch secret for '{}': {}", clientId, e.getMessage());
            throw new RuntimeException("Failed to fetch client secret", e);
        }
    }

    @Override
    public String getProductUUID(String realm, String clientId, String token) {
        log.debug("Resolving UUID for product '{}' in realm '{}'", clientId, realm);
        String url = buildUrl("/admin/realms/" + realm + "/clients?clientId=" + clientId);
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers), new ParameterizedTypeReference<>() {});

            List<Map<String, Object>> clients = response.getBody();
            if (clients != null && !clients.isEmpty()) {
                String uuid = (String) clients.get(0).get("id");
                log.debug("Resolved product UUID for '{}': {}", clientId, uuid);
                return uuid;
            }
            throw new RuntimeException("Product not found: " + clientId);
        } catch (Exception e) {
            log.error("Failed to resolve product UUID for '{}': {}", clientId, e.getMessage());
            throw new RuntimeException("Product not found: " + clientId, e);
        }
    }

    @Override
    public String getProductId(String realm, String clientId, String token) {
        return getProductUUID(realm, clientId, token);
    }

    private String fetchProductSecretByClientId(String realm, String clientId) {
        log.debug("Fetching product secret for client '{}' in realm '{}'", clientId, realm);
        try {
            String adminToken = getMasterToken();
            return getProductSecret(realm, clientId, adminToken);
        } catch (Exception e) {
            log.error("Failed to fetch product secret for '{}': {}", clientId, e.getMessage());
            throw new RuntimeException("Failed to fetch client secret for client " + clientId, e);
        }
    }



    // ==================== USER MANAGEMENT ====================

    @Override
    public String createUser(String realm, String token, Map<String, Object> userPayload) {
        String username = (String) userPayload.get("username");
        log.info("Creating user '{}' in realm '{}'", username, realm);
        userPayload.put("emailVerified", true);

        String url = buildUrl("/admin/realms/" + realm + "/users");
        HttpHeaders headers = createJsonHeaders(token);

        try {
            ResponseEntity<Void> response = restTemplate.postForEntity(url, new HttpEntity<>(userPayload, headers), Void.class);
            if (response.getStatusCode() == HttpStatus.CREATED) {
                String location = response.getHeaders().getFirst("Location");
                if (location != null) {
                    String userId = location.substring(location.lastIndexOf("/") + 1);
                    log.info("User '{}' created successfully with ID: {}", username, userId);
                    return userId;
                }
            }
            throw new RuntimeException("Failed to create user - status: " + response.getStatusCode());
        } catch (Exception e) {
            log.error("Failed to create user '{}': {}", username, e.getMessage());
            throw new RuntimeException("Failed to create user", e);
        }
    }

    @Override
    public List<Map<String, Object>> getAllUsers(String realm, String token) {
        log.info("Fetching all users in realm '{}'", realm);
        String url = buildUrl("/admin/realms/" + realm + "/users");
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        } catch (Exception e) {
            log.error("Failed to fetch users for realm '{}': {}", realm, e.getMessage());
            throw new RuntimeException("Failed to fetch users", e);
        }
    }

    @Override
    public void updateUser(String realm, String username, String token, Map<String, Object> userPayload) {
        log.info("Updating user '{}' in realm '{}'", username, realm);
        String userId = resolveUserId(realm, username, token);
        if (userId == null || userId.isBlank()) {
            throw new RuntimeException("User ID could not be resolved for username: " + username);
        }

        String url = buildUrl("/admin/realms/" + realm + "/users/" + userId);
        HttpHeaders headers = createJsonHeaders(token);
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(userPayload, headers);

        try {
            restTemplate.exchange(url, HttpMethod.PUT, entity, Void.class);
            log.info("User '{}' updated successfully", username);
        } catch (HttpClientErrorException e) {
            log.error("Failed to update user '{}': {} - {}", username, e.getStatusCode(), e.getResponseBodyAsString());
            throw e;
        }
    }

    @Override
    public void deleteUser(String realm, String username, String token) {
        log.info("Deleting user '{}' from realm '{}'", username, realm);
        String userId = resolveUserId(realm, username, token);
        if (userId == null || userId.isBlank()) {
            throw new RuntimeException("User ID could not be resolved for username: " + username);
        }

        String url = buildUrl("/admin/realms/" + realm + "/users/" + userId);
        HttpHeaders headers = createBearerHeaders(token);

        try {
            restTemplate.exchange(url, HttpMethod.DELETE, new HttpEntity<>(headers), Void.class);
            log.info("User '{}' deleted successfully", username);
        } catch (HttpClientErrorException e) {
            log.error("Failed to delete user '{}': {} - {}", username, e.getStatusCode(), e.getResponseBodyAsString());
            throw e;
        }
    }

    private String resolveUserId(String realm, String username, String token) {
        log.debug("Resolving user ID for username '{}' in realm '{}'", username, realm);
        String url = buildUrl("/admin/realms/" + realm + "/users?username=" + username);
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            List<Map<String, Object>> users = objectMapper.readValue(response.getBody(), new TypeReference<>() {});

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
            log.debug("Resolved user ID for username '{}': {}", username, userId);
            return userId;
        } catch (Exception e) {
            log.error("Failed to resolve user ID for '{}': {}", username, e.getMessage());
            throw new RuntimeException("Failed to resolve user ID for: " + username, e);
        }
    }


    // ==================== ROLE MANAGEMENT ====================

    @Override
    public void createProductRoles(String realm, String clientId, List<RoleCreationRequest> roleRequests, String token) {
        log.info("Creating {} roles for product '{}' in realm '{}'", roleRequests.size(), clientId, realm);
        String clientUUID = getProductUUID(realm, clientId, token);
        String keycloakUrl = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID + "/roles");
        HttpHeaders headers = createJsonHeaders(token);

        Set<String> processedRoles = new HashSet<>();
        List<String> failedRoles = new ArrayList<>();

        for (RoleCreationRequest role : roleRequests) {
            String roleName = role.getName();
            if (!processedRoles.add(roleName)) {
                log.debug("Skipping duplicate role '{}' in same request", roleName);
                continue;
            }

            if (createRoleInKeycloak(keycloakUrl, roleName, role.getDescription(), headers)) {
                registerRoleInProjectManager(realm, clientId, role);
            } else {
                failedRoles.add(roleName);
            }
        }

        if (!failedRoles.isEmpty()) {
            throw new RuntimeException("Failed to create roles: " + String.join(", ", failedRoles));
        }
    }

    private boolean createRoleInKeycloak(String url, String roleName, String description, HttpHeaders headers) {
        Map<String, Object> body = Map.of("name", roleName, "description", description);
        try {
            restTemplate.postForEntity(url, new HttpEntity<>(body, headers), String.class);
            log.info("Role '{}' created in Keycloak", roleName);
            return true;
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode().value() == 409) {
                log.info("Role '{}' already exists in Keycloak", roleName);
                return true;
            }
            log.error("Failed to create role '{}': {}", roleName, e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Unexpected error creating role '{}': {}", roleName, e.getMessage());
            return false;
        }
    }

    private void registerRoleInProjectManager(String realm, String clientId, RoleCreationRequest role) {
        try {
            WebClient pmWebClient = WebClient.builder().baseUrl(projectManagementBaseUrl).build();
            RoleRequest pmRequest = new RoleRequest();
            pmRequest.setRealmName(realm);
            pmRequest.setProductName(clientId);
            pmRequest.setRoleName(role.getName());
            pmRequest.setUri(role.getUri());
            pmRequest.setHttpMethod(role.getHttpMethod());

            pmWebClient.post()
                .uri("/project/roles/save-or-update")
                .bodyValue(pmRequest)
                .retrieve()
                .toBodilessEntity()
                .block();

            log.debug("Role '{}' registered in Project Manager", role.getName());
        } catch (Exception e) {
            log.warn("Project Manager registration failed for role '{}': {}", role.getName(), e.getMessage());
        }
    }

    @Override
    public List<Map<String, Object>> getProductRoles(String realm, String clientId, String token) {
        log.info("Fetching roles for product '{}' in realm '{}'", clientId, realm);
        String clientUUID = getProductUUID(realm, clientId, token);
        String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID + "/roles");
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers), new ParameterizedTypeReference<>() {});
            return response.getBody() != null ? response.getBody() : Collections.emptyList();
        } catch (Exception e) {
            log.error("Failed to fetch roles for product '{}': {}", clientId, e.getMessage());
            throw new RuntimeException("Failed to fetch product roles", e);
        }
    }

    @Override
    public List<Map<String, Object>> getAllRoles(String realm, String clientId, String token) {
        return getProductRoles(realm, clientId, token);
    }

    @Override
    public boolean updateRole(String realm, String clientId, String roleName, RoleCreationRequest role, String token) {
        log.info("Updating role '{}' for product '{}' in realm '{}'", roleName, clientId, realm);
        try {
            String clientUUID = getProductUUID(realm, clientId, token);
            String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID + "/roles/" + roleName);
            Map<String, Object> body = Map.of("name", role.getName(), "description", role.getDescription());
            HttpHeaders headers = createJsonHeaders(token);
            restTemplate.exchange(url, HttpMethod.PUT, new HttpEntity<>(body, headers), Void.class);
            log.info("Role '{}' updated successfully", roleName);
            return true;
        } catch (HttpClientErrorException.NotFound e) {
            log.error("Role '{}' not found in product '{}'", roleName, clientId);
            throw new RuntimeException("Role not found: " + roleName);
        } catch (Exception e) {
            log.error("Failed to update role '{}': {}", roleName, e.getMessage());
            throw new RuntimeException("Failed to update role", e);
        }
    }

    @Override
    public void deleteProductRole(String realm, String clientId, String roleName, String token) {
        log.info("Deleting role '{}' from product '{}' in realm '{}'", roleName, clientId, realm);
        try {
            String clientUUID = getProductUUID(realm, clientId, token);
            String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID + "/roles/" + roleName);
            HttpHeaders headers = createBearerHeaders(token);
            ResponseEntity<Void> response = restTemplate.exchange(url, HttpMethod.DELETE, new HttpEntity<>(headers), Void.class);
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("Keycloak refused delete: " + response.getStatusCode());
            }
            log.info("Role '{}' deleted successfully", roleName);
        } catch (HttpClientErrorException.NotFound e) {
            log.error("Role '{}' not found", roleName);
            throw new RuntimeException("Role not found: " + roleName);
        } catch (Exception e) {
            log.error("Failed to delete role '{}': {}", roleName, e.getMessage());
            throw new RuntimeException("Failed to delete product role", e);
        }
    }

    @Override
    public void createRealmRole(String realm, String roleName, String clientId, String token) {
        log.info("Creating realm-level role '{}' in realm '{}'", roleName, realm);
        String url = buildUrl("/admin/realms/" + realm + "/roles");
        Map<String, Object> body = Map.of("name", roleName);
        HttpHeaders headers = createJsonHeaders(token);
        try {
            restTemplate.postForEntity(url, new HttpEntity<>(body, headers), String.class);
            log.info("Realm role '{}' created successfully", roleName);
        } catch (Exception e) {
            log.error("Failed to create realm role '{}': {}", roleName, e.getMessage());
            throw new RuntimeException("Failed to create realm role", e);
        }
    }

    @Override
    public boolean createRole(String realm, String clientUUID, RoleCreationRequest role, String token) {
        log.info("Creating role '{}' for product UUID '{}' in realm '{}'", role.getName(), clientUUID, realm);
        try {
            String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID + "/roles");
            Map<String, Object> body = Map.of("name", role.getName(), "description", role.getDescription());
            HttpHeaders headers = createJsonHeaders(token);
            restTemplate.postForEntity(url, new HttpEntity<>(body, headers), String.class);
            log.info("Role '{}' created successfully", role.getName());
            return true;
        } catch (Exception e) {
            log.error("Failed to create role '{}': {}", role.getName(), e.getMessage());
            return false;
        }
    }

    @Override
    public void assignProductRolesByName(String realm, String username, String clientId, String token, List<AssignRoleRequest> roles) {
        log.info("Assigning {} roles to user '{}' for product '{}' in realm '{}'", roles.size(), username, clientId, realm);
        String userId = resolveUserId(realm, username, token);
        String clientUUID = getProductUUID(realm, clientId, token);
        List<Map<String, Object>> resolvedRoles = resolveRolesByName(realm, clientUUID, roles, token);
        assignRolesToUser(realm, userId, clientUUID, resolvedRoles, token);
        log.info("Successfully assigned {} roles to user '{}'", roles.size(), username);
    }

    private List<Map<String, Object>> resolveRolesByName(String realm, String clientUUID, List<AssignRoleRequest> roles, String token) {
        List<Map<String, Object>> resolvedRoles = new ArrayList<>();
        for (AssignRoleRequest role : roles) {
            if (role.getName() == null || role.getName().isBlank()) {
                throw new IllegalArgumentException("Role name must not be null or empty");
            }
            Map<String, Object> resolvedRole = fetchRoleByName(realm, clientUUID, role.getName(), token);
            resolvedRoles.add(resolvedRole);
        }
        return resolvedRoles;
    }

    private Map<String, Object> fetchRoleByName(String realm, String clientUUID, String roleName, String token) {
        String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID + "/roles/" + roleName);
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers), new ParameterizedTypeReference<>() {});
            Map<String, Object> role = response.getBody();
            if (role == null) {
                throw new RuntimeException("Role not found: " + roleName);
            }
            return Map.of("id", role.get("id"), "name", role.get("name"));
        } catch (Exception e) {
            log.error("Failed to fetch role '{}': {}", roleName, e.getMessage());
            throw new RuntimeException("Role not found: " + roleName, e);
        }
    }

    private void assignRolesToUser(String realm, String userId, String clientUUID, List<Map<String, Object>> roles, String token) {
        String url = buildUrl("/admin/realms/" + realm + "/users/" + userId + "/role-mappings/clients/" + clientUUID);
        HttpHeaders headers = createJsonHeaders(token);
        HttpEntity<List<Map<String, Object>>> request = new HttpEntity<>(roles, headers);

        try {
            restTemplate.postForEntity(url, request, Void.class);
            log.info("Assigned {} roles to user ID: {}", roles.size(), userId);
        } catch (Exception e) {
            log.error("Failed to assign roles: {}", e.getMessage());
            throw new RuntimeException("Failed to assign roles", e);
        }
    }

    @Override
    public void updateUserProductRoles(String realm, String username, String clientId, String oldRole, String newRole, String token) {
        log.info("Updating user '{}' role: '{}' → '{}' for product '{}' in realm '{}'", username, oldRole, newRole, clientId, realm);
        try {
            String userId = resolveUserId(realm, username, token);
            String clientUUID = getProductUUID(realm, clientId, token);
            String rolesUrl = buildUrl("/admin/realms/" + realm + "/users/" + userId + "/role-mappings/clients/" + clientUUID);
            HttpHeaders headers = createJsonHeaders(token);

            Map<String, Object> oldRoleRep = fetchRoleByName(realm, clientUUID, oldRole, token);
            restTemplate.exchange(rolesUrl, HttpMethod.DELETE, new HttpEntity<>(List.of(oldRoleRep), headers), Void.class);

            Map<String, Object> newRoleRep = fetchRoleByName(realm, clientUUID, newRole, token);
            restTemplate.exchange(rolesUrl, HttpMethod.POST, new HttpEntity<>(List.of(newRoleRep), headers), Void.class);

            log.info("Role swapped successfully for user '{}'", username);
        } catch (HttpClientErrorException e) {
            log.error("HTTP {} - {}", e.getStatusCode(), e.getResponseBodyAsString());
            throw e;
        }
    }

    @Override
    public void deleteUserProductRole(String realm, String username, String clientId, String roleName, String token) {
        log.info("Removing role '{}' from user '{}' for product '{}' in realm '{}'", roleName, username, clientId, realm);
        try {
            String userId = resolveUserId(realm, username, token);
            String clientUUID = getProductUUID(realm, clientId, token);
            String rolesUrl = buildUrl("/admin/realms/" + realm + "/users/" + userId + "/role-mappings/clients/" + clientUUID);
            Map<String, Object> roleRep = fetchRoleByName(realm, clientUUID, roleName, token);
            HttpHeaders headers = createJsonHeaders(token);
            restTemplate.exchange(rolesUrl, HttpMethod.DELETE, new HttpEntity<>(List.of(roleRep), headers), Void.class);
            log.info("Role '{}' removed successfully from user '{}'", roleName, username);
        } catch (HttpClientErrorException e) {
            log.error("HTTP {} - {}", e.getStatusCode(), e.getResponseBodyAsString());
            throw e;
        }
    }

    private void assignRealmManagementRoleToUser(String realm, String userId, String roleName, String token) {
        log.debug("Assigning realm management role '{}' to user ID '{}'", roleName, userId);
        String clientId = getRealmManagementClientId(realm, token);
        String roleId = getRealmManagementRoleId(realm, roleName, token);
        String url = buildUrl("/admin/realms/" + realm + "/users/" + userId + "/role-mappings/clients/" + clientId);
        HttpHeaders headers = createJsonHeaders(token);
        List<Map<String, Object>> roles = List.of(Map.of("id", roleId, "name", roleName));

        try {
            restTemplate.postForEntity(url, new HttpEntity<>(roles, headers), String.class);
            log.debug("Realm management role '{}' assigned to user ID '{}'", roleName, userId);
        } catch (Exception e) {
            log.error("Failed to assign realm role '{}' to user ID '{}': {}", roleName, userId, e.getMessage());
            throw new RuntimeException("Failed to assign realm role to user", e);
        }
    }

    private String getRealmManagementClientId(String realm, String token) {
        log.debug("Fetching realm-management client ID for realm '{}'", realm);
        String url = buildUrl("/admin/realms/" + realm + "/clients?clientId=" + REALM_MANAGEMENT_CLIENT);
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers), new ParameterizedTypeReference<>() {});
            if (response.getBody() != null && !response.getBody().isEmpty()) {
                String clientId = (String) response.getBody().get(0).get("id");
                log.debug("Found realm-management client ID: {}", clientId);
                return clientId;
            }
            throw new RuntimeException("realm-management client not found in realm '" + realm + "'");
        } catch (Exception e) {
            log.error("Failed to fetch realm-management client ID: {}", e.getMessage());
            throw new RuntimeException("realm-management client not found", e);
        }
    }

    private String getRealmManagementRoleId(String realm, String roleName, String token) {
        log.debug("Fetching realm management role ID for role '{}'", roleName);
        String clientId = getRealmManagementClientId(realm, token);
        String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientId + "/roles/" + roleName);
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            Map<String, Object> role = objectMapper.readValue(response.getBody(), new TypeReference<>() {});
            return (String) role.get("id");
        } catch (Exception e) {
            log.error("Failed to fetch realm management role ID for '{}': {}", roleName, e.getMessage());
            throw new RuntimeException("Failed to fetch role ID: " + roleName, e);
        }
    }


    // ==================== SIGNUP & PROVISIONING ====================

    @Override
    public SignupStatus signup(String realmName, String adminPassword) {
        validateSignupInput(realmName, adminPassword);
        SignupStatus status = initializeSignupStatus();
        String realm = realmName.trim();
        String clientId = realm + "-admin-product";

        try {
            String masterToken = executeMasterTokenStep(status);
            executeCreateRealmStep(status, realm, masterToken);
            executeCreateClientStep(status, realm, clientId, masterToken);
            String userId = executeCreateAdminUserStep(status, realm, adminPassword, masterToken);
            executeAssignAdminRolesStep(status, realm, userId, masterToken);
            increaseTokenTiming(realm, masterToken);

            status.setStatus("SUCCESS");
            status.setMessage("Signup completed successfully");
            log.info("Signup completed successfully for realm '{}'", realm);
            return status;
        } catch (Exception e) {
            log.error("Signup failed for realm '{}': {}", realm, e.getMessage());
            status.setStatus("FAILED");
            status.setMessage("Signup failed: " + e.getMessage());
            return status;
        }
    }

    private void validateSignupInput(String realmName, String adminPassword) {
        if (realmName == null || realmName.isBlank()) {
            throw new IllegalArgumentException("Realm name is required");
        }
        if (adminPassword == null || adminPassword.isBlank()) {
            throw new IllegalArgumentException("Admin password is required");
        }
    }

    private SignupStatus initializeSignupStatus() {
        return SignupStatus.builder()
            .status("IN_PROGRESS")
            .message("Signup started")
            .steps(new ArrayList<>())
            .build();
    }

    private String executeMasterTokenStep(SignupStatus status) {
        status.addStep("Get Master Token", "IN_PROGRESS", "Authenticating with Keycloak");
        String masterToken = getMasterToken();
        status.addStep("Get Master Token", "SUCCESS", "Token retrieved");
        return masterToken;
    }

    private void executeCreateRealmStep(SignupStatus status, String realm, String token) {
        status.addStep("Create Realm", "IN_PROGRESS", "Creating realm " + realm);
        createRealm(realm, token);
        status.addStep("Create Realm", "SUCCESS", "Realm created");
    }

    private String executeCreateClientStep(SignupStatus status, String realm, String clientId, String token) {
        status.addStep("Create Client", "IN_PROGRESS", "Creating admin client " + clientId);
        String clientUUID = createAdminClient(realm, clientId, token);
        status.addStep("Create Client", "SUCCESS", "Client created: " + clientUUID);
        return clientUUID;
    }

    private String executeCreateAdminUserStep(SignupStatus status, String realm, String adminPassword, String token) {
        status.addStep("Create Admin User", "IN_PROGRESS", "Creating admin user");
        Map<String, Object> userPayload = buildAdminUserPayload(adminPassword);
        String userId = createUser(realm, token, userPayload);
        status.addStep("Create Admin User", "SUCCESS", "Admin user created");
        return userId;
    }

    private void executeAssignAdminRolesStep(SignupStatus status, String realm, String userId, String token) {
        status.addStep("Assign Roles", "IN_PROGRESS", "Assigning admin permissions");
        List<String> adminRoles = List.of("create-client", "impersonation", "manage-realm", "manage-users", "manage-clients");
        for (String role : adminRoles) {
            assignRealmManagementRoleToUser(realm, userId, role, token);
        }
        status.addStep("Assign Roles", "SUCCESS", "Admin roles assigned");
    }

    private Map<String, Object> buildAdminUserPayload(String adminPassword) {
        Map<String, Object> userPayload = new HashMap<>();
        userPayload.put("username", ADMIN_USERNAME);
        userPayload.put("email", ADMIN_EMAIL);
        userPayload.put("firstName", "Admin");
        userPayload.put("lastName", "User");
        userPayload.put("enabled", true);
        userPayload.put("emailVerified", true);
        userPayload.put("requiredActions", Collections.emptyList());
        userPayload.put("credentials", List.of(Map.of("type", "password", "value", adminPassword, "temporary", false)));
        return userPayload;
    }

    private String createAdminClient(String realm, String clientId, String token) {
        log.debug("Creating admin client '{}' in realm '{}'", clientId, realm);
        String url = buildUrl("/admin/realms/" + realm + "/clients");
        Map<String, Object> body = new HashMap<>();
        body.put("clientId", clientId);
        body.put("enabled", true);
        body.put("protocol", PROTOCOL_OPENID_CONNECT);
        body.put("publicClient", false);
        body.put("clientAuthenticatorType", "client-secret");
        body.put("directAccessGrantsEnabled", true);
        body.put("serviceAccountsEnabled", true);
        body.put("standardFlowEnabled", false);
        body.put("implicitFlowEnabled", false);
        body.put("bearerOnly", false);

        HttpHeaders headers = createJsonHeaders(token);

        try {
            restTemplate.exchange(url, HttpMethod.POST, new HttpEntity<>(body, headers), Void.class);
            String clientUUID = getProductUUID(realm, clientId, token);
            ensureClientSecret(realm, clientUUID, token);
            log.info("Admin client '{}' created successfully with UUID: {}", clientId, clientUUID);
            return clientUUID;
        } catch (Exception e) {
            log.error("Failed to create admin client: {}", e.getMessage());
            throw new RuntimeException("Failed to create admin client", e);
        }
    }

    private void increaseTokenTiming(String realm, String token) {
        Map<String, Object> tokenConfig = Map.of(
            "accessTokenLifespan", TOKEN_LIFESPAN_SECONDS,
            "ssoSessionIdleTimeout", SSO_SESSION_IDLE_TIMEOUT,
            "ssoSessionMaxLifespan", SSO_SESSION_MAX_LIFESPAN);

        try {
            webClient.put()
                .uri(buildUrl("/admin/realms/" + realm))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .bodyValue(tokenConfig)
                .retrieve()
                .toBodilessEntity()
                .block();

            log.debug("Token timing updated for realm: {}", realm);
        } catch (Exception e) {
            log.warn("Failed to update token timing for realm '{}': {}", realm, e.getMessage());
        }
    }


    // ==================== HTTP REQUEST HELPERS ====================

    private MultiValueMap<String, String> buildTokenRequestBody(String grantType, String clientId,
                                                                 String username, String password,
                                                                 String clientSecret) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", grantType);
        body.add("client_id", clientId);
        if (clientSecret != null && !clientSecret.isBlank()) {
            body.add("client_secret", clientSecret);
        }
        body.add("username", username);
        body.add("password", password);
        return body;
    }

    private Map<String, Object> executeTokenRequest(String tokenUrl, MultiValueMap<String, String> body) {
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, createFormHeaders());
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
            tokenUrl, HttpMethod.POST, request, new ParameterizedTypeReference<>() {});

        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new RuntimeException("Failed to get token - status: " + response.getStatusCode());
        }
        return response.getBody();
    }


    // ==================== ZIP & FILE PROVISIONING ====================

    private void extractZipFile(MultipartFile zipFile, Path extractPath) throws IOException {
        try {
            org.apache.commons.compress.archivers.zip.ZipArchiveInputStream zis =
                new org.apache.commons.compress.archivers.zip.ZipArchiveInputStream(zipFile.getInputStream());
            org.apache.commons.compress.archivers.ArchiveEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path resolvedPath = extractPath.resolve(entry.getName()).normalize();
                validateZipPath(resolvedPath, extractPath);
                if (entry.isDirectory()) {
                    Files.createDirectories(resolvedPath);
                } else {
                    Files.createDirectories(resolvedPath.getParent());
                    Files.copy(zis, resolvedPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
            zis.close();
            log.debug("ZIP file extracted successfully to {}", extractPath);
        } catch (Exception e) {
            log.error("ZIP extraction failed: {}", e.getMessage());
            throw new IOException("Failed to extract ZIP file. Ensure ZIP is valid and uses standard DEFLATE compression.", e);
        }
    }

    private void validateZipPath(Path resolvedPath, Path basePath) throws IOException {
        if (!resolvedPath.startsWith(basePath)) {
            throw new IOException("Invalid ZIP entry: path traversal detected");
        }
    }

    private void uploadDirectoryToGitHub(Path root, String repo) throws Exception {
        Files.walk(root)
            .filter(Files::isRegularFile)
            .forEach(file -> {
                try {
                    String relativePath = root.relativize(file).toString().replace("\\", "/");
                    byte[] content = Files.readAllBytes(file);
                    uploadFileToGithub(relativePath, content, repo);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to upload file to GitHub: " + e.getMessage(), e);
                }
            });
    }

    private void uploadFileToGithub(String path, byte[] content, String repo) throws Exception {
        String apiUrl = buildGithubApiUrl(repo, path);
        String base64Content = Base64.getEncoder().encodeToString(content);
        String payload = buildGithubUploadPayload(base64Content);

        HttpURLConnection conn = (HttpURLConnection) new java.net.URL(apiUrl).openConnection();
        conn.setRequestMethod("PUT");
        configureGithubConnection(conn);

        try (var out = conn.getOutputStream()) {
            out.write(payload.getBytes());
        }

        int responseCode = conn.getResponseCode();
        if (responseCode >= 300) {
            throw new RuntimeException("GitHub upload failed for: " + path + " (HTTP " + responseCode + ")");
        }
    }

    private String buildGithubApiUrl(String repo, String path) {
        return "https://api.github.com/repos/" + provisioningService.getGithubOrg() + "/" + repo + "/contents/" + path;
    }

    private String buildGithubUploadPayload(String base64Content) {
        return String.format("{\"message\": \"initial commit\", \"content\": \"%s\"}", base64Content);
    }

    private void configureGithubConnection(HttpURLConnection conn) {
        conn.setRequestProperty("Authorization", "Bearer " + provisioningService.getGithubToken());
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
    }

    private void handleProvisioningFailure(SignupStatus status, Exception e) {
        status.setStatus("FAILED");
        status.setMessage(e.getMessage());
        if (!status.getSteps().isEmpty()) {
            SignupStatus.StepStatus lastStep = status.getSteps().get(status.getSteps().size() - 1);
            if ("IN_PROGRESS".equals(lastStep.getStatus())) {
                lastStep.setStatus("FAILED");
                lastStep.setError(e.getMessage());
            }
        }
    }


    // ==================== UTILITY & HELPER METHODS ====================

    private String buildUrl(String path) {
        return config.getBaseUrl() + path;
    }

    private HttpHeaders createFormHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return headers;
    }

    private HttpHeaders createBearerHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }

    private HttpHeaders createJsonHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    private void cleanupDirectory(Path dir) {
        if (dir == null || !Files.exists(dir)) {
            return;
        }
        try (var walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder())
                .forEach(p -> {
                    try {
                        Files.delete(p);
                    } catch (Exception ignored) {
                    }
                });
            log.debug("Temporary directory cleaned up: {}", dir);
        } catch (Exception e) {
            log.warn("Failed to cleanup directory {}: {}", dir, e.getMessage());
        }
    }
}

