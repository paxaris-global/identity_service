package com.paxaris.identity_service.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
// import com.paxaris.identity_service.service.DockerHubService;
// import com.paxaris.identity_service.service.DockerBuildService;
import com.paxaris.identity_service.dto.*;
import com.paxaris.identity_service.service.KeycloakClientService;
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
import java.net.URL;
import java.io.IOException;

@Service
@RequiredArgsConstructor
public class KeycloakClientServiceImpl implements KeycloakClientService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakClientServiceImpl.class);

    private final KeycloakConfig config;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final ProvisioningService provisioningService;
    // private final DockerHubService dockerHubService;
    // private final DockerBuildService dockerBuildService;
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
                    "401 Unauthorized: Keycloak master admin credentials or client-id is incorrect. Please check your configuration. Username: {}, Client-ID: {}",
                    config.getAdminUsername(), "admin-cli");
            throw new RuntimeException("Authentication failed for master token.", e);
        } catch (Exception e) {
            log.error("Failed to get master token due to an error: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to connect to Keycloak token endpoint.", e);
        }
    }

    @Override
    public Map<String, Object> getRealmToken(String realm,
            String username,
            String password,
            String clientId,
            String clientSecret) {

        String tokenUrl = config.getBaseUrl() + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", clientId);
        if (clientSecret != null && !clientSecret.isBlank()) {
            body.add("client_secret", clientSecret);
        }
        body.add("username", username);
        body.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, Map.class);

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                throw new RuntimeException("Failed to get token for realm " + realm);
            }

            return response.getBody();
        } catch (HttpClientErrorException e) {
            throw new RuntimeException("Login failed: " + e.getResponseBodyAsString(), e);
        }
    }

    @Override
    public Map<String, Object> getMyRealmToken(String username, String password, String clientId, String realm) {
        log.info("🚀 Starting login flow for user '{}' in realm '{}'", username, realm);

        try {
            // 1️⃣ Get admin/master token
            String adminToken = getMasterToken();
            log.info("🔐 Master token retrieved", adminToken);

            // 2️⃣ Fetch client secret dynamically, skip for admin-cli
            String clientSecret = null; // declare outside
            if (!"admin-cli".equals(clientId)) {
                clientSecret = getClientSecretFromKeycloak(realm, clientId);
                log.info("🔐 Client secret retrieved for client '{}': {}", clientId, clientSecret);
            } else {
                log.info("⚠️ Skipping client secret fetch for 'admin-cli'");
            }

            // 3️⃣ Build token URL
            String tokenUrl = config.getBaseUrl() + "/realms/" + realm + "/protocol/openid-connect/token";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("grant_type", "password");
            formData.add("client_id", clientId);
            if (clientSecret != null) {
                formData.add("client_secret", clientSecret); // only add if not null
            }
            formData.add("username", username);
            formData.add("password", password);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(formData, headers);

            // 4️⃣ Request user access token
            ResponseEntity<String> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, String.class);

            // 5️⃣ Return parsed token JSON
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {
            });

        } catch (Exception e) {
            log.error("💥 Failed to get realm token for user '{}': {}", username, e.getMessage(), e);
            throw new RuntimeException("Failed to get realm token", e);
        }
    }

    private String getClientSecretFromKeycloak(String realm, String clientId) {
        log.info("Fetching client secret for client '{}' in realm '{}'", clientId, realm);

        try {
            // Step 1: Get admin token
            String adminToken = getMasterToken();
            log.debug("Admin token retrieved: [HIDDEN]");

            // Step 2: Get client internal ID
            String clientsUrl = config.getBaseUrl() + "/admin/realms/" + realm + "/clients?clientId=" + clientId;
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(adminToken);
            HttpEntity<Void> request = new HttpEntity<>(headers);

            ResponseEntity<List<Map<String, Object>>> clientsResponse = restTemplate.exchange(
                    clientsUrl,
                    HttpMethod.GET,
                    request,
                    new ParameterizedTypeReference<>() {
                    });

            List<Map<String, Object>> clients = clientsResponse.getBody();
            if (clients == null || clients.isEmpty()) {
                throw new RuntimeException("Client not found in Keycloak for clientId: " + clientId);
            }

            String internalClientId = (String) clients.get(0).get("id");
            log.info("Found internal client ID: {}", internalClientId);

            // Step 3: Get the secret for this client
            String secretUrl = config.getBaseUrl() + "/admin/realms/" + realm + "/clients/" + internalClientId
                    + "/client-secret";
            ResponseEntity<Map<String, Object>> secretResponse = restTemplate.exchange(
                    secretUrl,
                    HttpMethod.GET,
                    request,
                    new ParameterizedTypeReference<>() {
                    });

            Map<String, Object> secretBody = secretResponse.getBody();
            if (secretBody == null || secretBody.get("value") == null) {
                throw new RuntimeException("Client secret not found for clientId: " + clientId);
            }

            String clientSecret = (String) secretBody.get("value");
            log.info("Successfully fetched client secret for '{}'", clientId);
            return clientSecret;

        } catch (Exception e) {
            log.error("Failed to fetch client secret for '{}': {}", clientId, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch client secret for client " + clientId, e);
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
    public String createClient(String realm, String clientId, boolean isPublicClient, String token) {
        // Correct Keycloak admin URL
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients";

        // Build request body
        Map<String, Object> body = new HashMap<>();
        body.put("clientId", clientId);
        body.put("enabled", true);
        body.put("protocol", "openid-connect");
        body.put("publicClient", isPublicClient);
        body.put("standardFlowEnabled", true);
        body.put("directAccessGrantsEnabled", true);
        body.put("authorizationServicesEnabled", true);

        if (isPublicClient) {
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

        // Make REST call to Keycloak
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to create client with status code: " + response.getStatusCode());
        }

        // Return the client UUID
        return getClientUUID(realm, clientId, token);
    }

    @Override
    public List<Map<String, Object>> getAllClients(String realm, String token) {
        log.info("Attempting to fetch all clients for realm '{}'", realm);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients";
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers),
                    String.class);
            log.info("Successfully fetched all clients for realm '{}'.", realm);
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {
            });
        } catch (Exception e) {
            log.error("Failed to fetch clients for realm '{}': {}", realm, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch clients", e);
        }
    }

    @Override
    public String getClientSecret(String realm, String clientId, String token) {
        log.info("Attempting to get client secret for client '{}' in realm '{}'", clientId, realm);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients/" + clientId + "/client-secret";
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            Map<String, Object> map = objectMapper.readValue(response.getBody(), new TypeReference<>() {
            });
            log.info("Successfully fetched client secret for client '{}'.", clientId);
            return (String) map.get("value");
        } catch (Exception e) {
            log.error("Failed to fetch client secret for client '{}': {}", clientId, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch client secret", e);
        }
    }

    @Override
    public String getClientUUID(String realm, String clientName, String token) {
        log.info("Attempting to get UUID for client '{}' in realm '{}'", clientName, realm);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients?clientId=" + clientName;
        if (token == null || !validateToken("master", token)) {
            token = getMasterToken();
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers),
                new ParameterizedTypeReference<>() {
                });
        if (response.getBody() != null && !response.getBody().isEmpty()) {
            String uuid = (String) response.getBody().get(0).get("id");
            log.info("Found UUID for client '{}': {}", clientName, uuid);
            return uuid;
        }
        log.error("Client not found: {}", clientName);
        throw new RuntimeException("Client not found: " + clientName);
    }

    @Override
    public String getClientId(String realm, String clientName, String token) {
        log.info("Attempting to get client ID for name '{}'", clientName);
        return getClientUUID(realm, clientName, token);
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
    public void createClientRoles(String realm, String clientName, List<RoleCreationRequest> roleRequests,
            String token) {
        log.info("Attempting to create {} client roles for client '{}' in realm '{}'", roleRequests.size(), clientName,
                realm);
        String clientUUID = getClientUUID(realm, clientName, token);
        log.info("Client UUID for '{}' is '{}'", clientName, clientUUID);

        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients/" + clientUUID + "/roles";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        List<String> failedRoles = new ArrayList<>();
        for (RoleCreationRequest role : roleRequests) {
            Map<String, Object> body = Map.of(
                    "name", role.getName(),
                    "description", role.getDescription());
            try {
                restTemplate.postForEntity(url, new HttpEntity<>(body, headers), String.class);
                log.info("Role '{}' created successfully.", role.getName());
            } catch (Exception e) {
                failedRoles.add(role.getName());
                log.error("Failed to create role '{}': {}", role.getName(), e.getMessage());
            }
        }

        if (!failedRoles.isEmpty()) {
            throw new RuntimeException("Failed to create roles: " + String.join(", ", failedRoles));
        }
    }

    @Override
    public void createRealmRole(String realm, String roleName, String clientId, String token) {
        log.info("Attempting to create realm role '{}' in realm '{}'", roleName, realm);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/roles";
        Map<String, Object> body = Map.of("name", roleName);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);

        try {
            restTemplate.postForEntity(url, new HttpEntity<>(body, headers), String.class);
            log.info("Realm role '{}' created successfully.", roleName);
        } catch (Exception e) {
            log.error("Failed to create realm role '{}': {}", roleName, e.getMessage());
        }
    }

    @Override
    public boolean createRole(String realm, String clientUUID, RoleCreationRequest role, String token) {
        log.info("Attempting to create role '{}' for client with UUID '{}' in realm '{}'", role.getName(), clientUUID,
                realm);
        try {
            String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients/" + clientUUID + "/roles";
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, Object> body = Map.of(
                    "name", role.getName(),
                    "description", role.getDescription());

            restTemplate.postForEntity(url, new HttpEntity<>(body, headers), String.class);
            log.info("Role '{}' created successfully.", role.getName());
            return true;
        } catch (Exception e) {
            log.error("Failed to create role '{}': {}", role.getName(), e.getMessage());
            return false;
        }
    }

    @Override
    public boolean updateRole(String realm, String clientUUID, String roleName, RoleCreationRequest role,
            String token) {
        log.info("Attempting to update role '{}' for client with UUID '{}' in realm '{}'", roleName, clientUUID, realm);
        try {
            String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients/" + clientUUID + "/roles/"
                    + roleName;
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, Object> body = Map.of(
                    "name", role.getName(),
                    "description", role.getDescription());

            restTemplate.put(url, new HttpEntity<>(body, headers));
            log.info("Role '{}' updated successfully.", roleName);
            return true;
        } catch (Exception e) {
            log.error("Failed to update role '{}': {}", roleName, e.getMessage());
            return false;
        }
    }

    @Override
    public boolean deleteRole(String realm, String clientUUID, String roleName, String token) {
        log.info("Attempting to delete role '{}' for client with UUID '{}' in realm '{}'", roleName, clientUUID, realm);
        try {
            String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients/" + clientUUID + "/roles/"
                    + roleName;
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);

            restTemplate.exchange(url, HttpMethod.DELETE, new HttpEntity<>(headers), String.class);
            log.info("Role '{}' deleted successfully.", roleName);
            return true;
        } catch (Exception e) {
            log.error("Failed to delete role '{}': {}", roleName, e.getMessage());
            return false;
        }
    }

    @Override
    public List<Map<String, Object>> getAllRoles(String realm, String clientId, String token) {
        log.info("Attempting to fetch all roles for client '{}' in realm '{}'", clientId, realm);
        String clientUUID = getClientUUID(realm, clientId, token);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients/" + clientUUID + "/roles";
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers),
                    String.class);
            log.info("Successfully fetched all roles for client '{}'.", clientId);
            return objectMapper.readValue(response.getBody(), new TypeReference<>() {
            });
        } catch (Exception e) {
            log.error("Failed to fetch roles for client '{}': {}", clientId, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch roles", e);
        }
    }

    // ---------------- ROLE ASSIGN ----------------
    @Override
    public void assignClientRole(String realm, String username, String clientName, String roleName, String token) {
        // Resolve IDs automatically
        String userId = resolveUserId(realm, username, token);
        String clientUUID = getClientUUID(realm, clientName, token);
        String roleId = getClientRoleId(realm, clientUUID, roleName, token);

        // Perform assignment
        assignClientRoleToUser(realm, userId, clientUUID, roleId, roleName, token);
    }

    @Override
    public void assignClientRoleToUser(String realm, String userId, String clientUUID, String roleId, String roleName,
            String token) {
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/clients/"
                + clientUUID;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Prepare role payload
        List<Map<String, Object>> roles = List.of(Map.of(
                "id", roleId,
                "name", roleName));

        try {
            restTemplate.postForEntity(url, new HttpEntity<>(roles, headers), String.class);
            log.info("Assigned role '{}' to user '{}' in client '{}'", roleName, userId, clientUUID);
        } catch (Exception e) {
            log.error("Failed to assign role '{}' to user '{}': {}", roleName, userId, e.getMessage(), e);
            throw new RuntimeException("Failed to assign client role: " + e.getMessage(), e);
        }
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
                request.getClientId(), request.getRealmName());
        if (sourceZip == null || sourceZip.isEmpty()) {
            throw new IllegalArgumentException("Source ZIP file is required");
        }
        if (request.getAdminUser() == null) {
            throw new IllegalArgumentException("Admin user information is required");
        }

        String masterToken = null;
        String realm = request.getRealmName() != null ? request.getRealmName() : "default-realm";
        String clientId = request.getClientId() != null ? request.getClientId() : "default-client";
        String adminUsername = request.getAdminUser().getUsername() != null ? request.getAdminUser().getUsername()
                : "admin";
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

            // Step 3: Create Client
            status.addStep("Create Client", "IN_PROGRESS", "Creating Keycloak client: " + clientId);
            log.info("🧩 Step 3: Creating client '{}'", clientId);
            String clientUUID = createClient(realm, clientId, request.isPublicClient(), masterToken);
            status.addStep("Create Client", "SUCCESS",
                    "Client '" + clientId + "' created successfully with UUID: " + clientUUID);

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
                    "temporary", false);
            userMap.put("credentials", List.of(credentials));

            String userId = createUser(realm, masterToken, userMap);
            status.addStep("Create Admin User", "SUCCESS", "Admin user '" + adminUsername + "' created successfully");

            // Step 5: Assign default roles
            status.addStep("Assign Admin Roles", "IN_PROGRESS", "Assigning default admin roles");
            log.info("🔑 Step 5: Assigning default admin roles to '{}'", adminUsername);
            List<String> defaultRoles = List.of("create-client", "impersonation", "manage-realm", "manage-users",
                    "manage-clients");
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
            roleRequest.setProductName(clientId);
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

            // Step 8: Generate repository name using realm, admin username, and client name
            String repoName = ProvisioningService.generateRepositoryName(realm, adminUsername, clientId);
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
            uploadDirectoryToGitHub(extractedCodePath, repoName); // <--- This call stays the same
            status.addStep("Upload Code to GitHub", "SUCCESS", "Code uploaded to GitHub successfully");

            // Step 10: Upload code to GitHub
            // status.addStep("Upload Code to GitHub", "IN_PROGRESS", "Uploading application
            // code to GitHub");ok
            // log.info("⬆️ Step 10: Uploading code to GitHub repository");
            // uploadDirectoryToGitHub(extractedCodePath, repoName);
            // status.addStep("Upload Code to GitHub", "SUCCESS", "Code uploaded to GitHub
            // successfully");

            // Step 11: Create Docker Hub Repository
            // if (dockerHubUsername == null || dockerHubUsername.isEmpty()) {
            // throw new IllegalStateException("Docker Hub username is not configured");
            // }
            // String dockerRepoName = dockerHubUsername + "/" + repoName;
            // status.addStep("Create Docker Hub Repository", "IN_PROGRESS",
            // "Creating Docker Hub repository: " + dockerRepoName);
            // log.info("🐳 Step 11: Creating Docker Hub repository '{}'", dockerRepoName);
            // dockerHubService.createRepository(dockerRepoName);
            // status.addStep("Create Docker Hub Repository", "SUCCESS",
            // "Docker Hub repository '" + dockerRepoName + "' created successfully");

            // // Step 12: Build Docker Image
            // String dockerImageName = dockerRepoName + ":latest";
            // status.addStep("Build Docker Image", "IN_PROGRESS", "Building Docker image: "
            // + dockerImageName);
            // log.info("🔨 Step 12: Building Docker image '{}'", dockerImageName);
            // boolean buildSuccess = dockerBuildService.buildDockerImage(extractedCodePath,
            // dockerImageName);
            // if (!buildSuccess) {
            // throw new RuntimeException("Docker image build failed");
            // }
            // status.addStep("Build Docker Image", "SUCCESS", "Docker image built
            // successfully");

            // // Step 13: Push Docker Image to Docker Hub
            // status.addStep("Push Docker Image", "IN_PROGRESS", "Pushing Docker image to
            // Docker Hub");
            // log.info("📤 Step 13: Pushing Docker image to Docker Hub");
            // boolean pushSuccess = dockerBuildService.pushDockerImage(dockerImageName);
            // if (!pushSuccess) {
            // throw new RuntimeException("Docker image push failed");
            // }
            // status.addStep("Push Docker Image", "SUCCESS", "Docker image pushed to Docker
            // Hub successfully");

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

    /**
     * Extract ZIP file using Apache Commons Compress for better compatibility
     */
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

    /**
     * Helper method to upload directory to GitHub (extracted from
     * ProvisioningService for reuse)
     */
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

    // ---------------- UTILITY ----------------
    private String resolveUserId(String realm, String username, String token) {
        log.info("Resolving user ID for username '{}' in realm '{}'", username, realm);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/users?username=" + username;
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers),
                    String.class);
            List<Map<String, Object>> users = objectMapper.readValue(response.getBody(), new TypeReference<>() {
            });
            if (users.isEmpty()) {
                log.error("User not found: {}", username);
                throw new RuntimeException("User not found: " + username);
            }
            String userId = (String) users.get(0).get("id");
            log.info("Resolved user ID: '{}' for username '{}'", userId, username);
            return userId;
        } catch (Exception e) {
            log.error("Failed to resolve user UUID for '{}': {}", username, e.getMessage(), e);
            throw new RuntimeException("Failed to resolve user UUID for: " + username, e);
        }
    }

    private String getClientRoleId(String realm, String clientUUID, String roleName, String token) {
        log.info("Fetching client role ID for role '{}' on client UUID '{}'", roleName, clientUUID);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients/" + clientUUID + "/roles";
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers),
                    String.class);
            List<Map<String, Object>> roles = objectMapper.readValue(response.getBody(), new TypeReference<>() {
            });
            String roleId = roles.stream()
                    .filter(r -> r.get("name").equals(roleName))
                    .map(r -> (String) r.get("id"))
                    .findFirst()
                    .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));
            log.info("Fetched role ID: '{}' for role name '{}'", roleId, roleName);
            return roleId;
        } catch (Exception e) {
            log.error("Failed to fetch client roles for client UUID '{}': {}", clientUUID, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch client roles", e);
        }
    }

    private void assignRealmManagementRoleToUser(String realm, String userId, String roleName, String token) {
        log.info("Assigning realm management role '{}' to user ID '{}'", roleName, userId);
        String clientId = getRealmManagementClientId(realm, token);
        String roleId = getRealmManagementRoleId(realm, roleName, token);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/clients/"
                + clientId;

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

    private String getRealmManagementClientId(String realm, String token) {
        log.info("Fetching realm-management client ID for realm '{}'", realm);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients?clientId=realm-management";
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers),
                new ParameterizedTypeReference<>() {
                });
        if (response.getBody() != null && !response.getBody().isEmpty()) {
            String clientId = (String) response.getBody().get(0).get("id");
            log.info("Found realm-management client ID: {}", clientId);
            return clientId;
        }
        log.error("realm-management client not found in realm '{}'.", realm);
        throw new RuntimeException("realm-management client not found");
    }

    private String getRealmManagementRoleId(String realm, String roleName, String token) {
        log.info("Fetching realm management role ID for role '{}'", roleName);
        String clientId = getRealmManagementClientId(realm, token);
        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients/" + clientId + "/roles/" + roleName;
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers),
                    String.class);
            Map<String, Object> role = objectMapper.readValue(response.getBody(), new TypeReference<>() {
            });
            String roleId = (String) role.get("id");
            log.info("Found realm management role ID: {}", roleId);
            return roleId;
        } catch (Exception e) {
            log.error("Failed to fetch realm management role ID for '{}': {}", roleName, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch role ID: " + roleName, e);
        }
    }
}
