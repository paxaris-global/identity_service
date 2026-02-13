package com.paxaris.identity_service.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.stream.Collectors;

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
    @Value("${project.management.base-url}")
    private String projectManagementBaseUrl;
    @Value("${docker.hub.username}")
    private String dockerHubUsername;
    private final WebClient webClient;

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
    public String getMasterTokenInternally() {
        return getMasterToken();
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
//    @Override
//    public String createClient(String realm, String clientId, boolean isPublicClient, String token) {
//        // Correct Keycloak admin URL
//        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients";
//
//        // Build request body
//        Map<String, Object> body = new HashMap<>();
//        body.put("clientId", clientId);
//        body.put("enabled", true);
//        body.put("protocol", "openid-connect");
//        body.put("publicClient", isPublicClient);
//        body.put("standardFlowEnabled", true);
//        body.put("directAccessGrantsEnabled", true);
////        body.put("authorizationServicesEnabled", true);
//
//        if (isPublicClient) {
//            body.put("clientAuthenticatorType", "client-id");
//            body.put("redirectUris", Collections.singletonList("*"));
//            body.put("serviceAccountsEnabled", false);
//        } else {
//            body.put("clientAuthenticatorType", "client-secret");
//            body.put("serviceAccountsEnabled", true);
//        }
//
//        // Set headers
//        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_JSON);
//        headers.setBearerAuth(token);
//
//        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);
//
//        // Make REST call to Keycloaks
//        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
//
//        if (!response.getStatusCode().is2xxSuccessful()) {
//            throw new RuntimeException("Failed to create client with status code: " + response.getStatusCode());
//        }
//
//        // Return the client UUID
//        return getClientUUID(realm, clientId, token);
//    }
private void ensureClientSecret(String realm, String clientUUID, String token) {

    String url = config.getBaseUrl()
            + "/admin/realms/" + realm
            + "/clients/" + clientUUID
            + "/client-secret";

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);

    ResponseEntity<Map> response = restTemplate.exchange(
            url,
            HttpMethod.POST,   // forces secret regeneration
            new HttpEntity<>(headers),
            Map.class
    );

    if (!response.getStatusCode().is2xxSuccessful()) {
        throw new RuntimeException("Failed to generate client secret");
    }
}

@Override
public String createClient(
        String realm,
        String clientId,
        boolean isPublicClient,
        String adminToken,
        MultipartFile sourceZip,
        SignupStatus status,
        String ownerUsername) {

    Path extractedCodePath = null;

    try {

        // ====================================================
        // Step 1 — Create Keycloak Client (ADMIN TOKEN ONLY)
        // ====================================================
        status.addStep("Create Client", "IN_PROGRESS", "Creating Keycloak client");

        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients";

        Map<String, Object> body = new HashMap<>();
        body.put("clientId", clientId);
        body.put("enabled", true);
        body.put("protocol", "openid-connect");

        if (isPublicClient) {

            // 🌍 PUBLIC FRONTEND CLIENT
            body.put("publicClient", true);
            body.put("standardFlowEnabled", true);          // browser login
            body.put("directAccessGrantsEnabled", false);
            body.put("serviceAccountsEnabled", false);
            body.put("redirectUris", List.of("*"));

        } else {

            // 🔐 CONFIDENTIAL BACKEND CLIENT
            body.put("publicClient", false);
            body.put("clientAuthenticatorType", "client-secret");
            body.put("serviceAccountsEnabled", true);
            body.put("directAccessGrantsEnabled", true);

            body.put("standardFlowEnabled", false);
            body.put("implicitFlowEnabled", false);
            body.put("bearerOnly", false);
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);

        restTemplate.exchange(
                url,
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                Void.class
        );

        String clientUUID = getClientUUID(realm, clientId, adminToken);

        // 🔑 ENSURE SECRET EXISTS FOR CONFIDENTIAL CLIENT
        if (!isPublicClient) {
            ensureClientSecret(realm, clientUUID, adminToken);
        }

        status.addStep(
                "Create Client",
                "SUCCESS",
                "Client created: " + clientUUID
        );
        // ====================================================
        // Step 2 — Extract ZIP
        // ====================================================
        status.addStep("Extract Application Code", "IN_PROGRESS", "Extracting ZIP");

        extractedCodePath = Files.createTempDirectory("signup-extract-");
        extractZipFile(sourceZip, extractedCodePath);

        status.addStep("Extract Application Code", "SUCCESS", "ZIP extracted");

        // ====================================================
        // Step 3 — Generate Repo Name
        // ====================================================
        String repoName = ProvisioningService.generateRepositoryName(
                realm,
                ownerUsername,
                clientId
        );

        status.addStep("Generate Repository Name", "SUCCESS",
                repoName);

        // ====================================================
        // Step 4 — Create GitHub Repository
        // ====================================================
        status.addStep("Create GitHub Repository", "IN_PROGRESS",
                "Creating " + repoName);

        provisioningService.createRepo(repoName);

        status.addStep("Create GitHub Repository", "SUCCESS",
                "Repository created");

        // ====================================================
        // Step 5 — Upload Code
        // ====================================================
        status.addStep("Upload Code to GitHub", "IN_PROGRESS",
                "Uploading code");

        uploadDirectoryToGitHub(extractedCodePath, repoName);

        status.addStep("Upload Code to GitHub", "SUCCESS",
                "Code uploaded");

        // ====================================================
        // Cleanup
        // ====================================================
        cleanupDirectory(extractedCodePath);

        status.setStatus("SUCCESS");
        status.setMessage("Provisioning completed successfully");

        return clientUUID;

    } catch (Exception e) {

        status.setStatus("FAILED");
        status.setMessage(e.getMessage());

        if (!status.getSteps().isEmpty()) {
            SignupStatus.StepStatus last =
                    status.getSteps().get(status.getSteps().size() - 1);

            if ("IN_PROGRESS".equals(last.getStatus())) {
                last.setStatus("FAILED");
                last.setError(e.getMessage());
            }
        }

        cleanupDirectory(extractedCodePath);

        throw new RuntimeException("Client provisioning failed", e);
    }
}
    private void cleanupDirectory(Path dir) {
        if (dir == null || !Files.exists(dir)) return;

        try {
            Files.walk(dir)
                    .sorted(Comparator.reverseOrder())
                    .forEach(p -> {
                        try { Files.delete(p); } catch (Exception ignored) {}
                    });
        } catch (Exception ignored) {}
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

//----------------------------------    update user
@Override
public void updateUser(
        String realm,
        String username,
        String token,
        Map<String, Object> userPayload) {

    log.info("🚀 Updating user '{}' in realm '{}'", username, realm);

    String userId = resolveUserId(realm, username, token);

    log.info("🆔 Resolved userId = {}", userId);

    if (userId == null || userId.isBlank()) {
        throw new RuntimeException("User ID could not be resolved for username: " + username);
    }

    String url = config.getBaseUrl()
            + "/admin/realms/" + realm
            + "/users/" + userId;

    log.info("🌐 Calling identity update URL: {}", url);
    log.info("📦 Sending payload: {}", userPayload);

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    headers.setContentType(MediaType.APPLICATION_JSON);

    HttpEntity<Map<String, Object>> entity =
            new HttpEntity<>(userPayload, headers);

    try {

        restTemplate.exchange(
                url,
                HttpMethod.PUT,
                entity,
                Void.class
        );

        log.info("✅ User updated successfully");

    } catch (HttpClientErrorException e) {

        log.error("❌ HTTP STATUS: {}", e.getStatusCode());
        log.error("❌ RESPONSE BODY: {}", e.getResponseBodyAsString());
        throw e;

    } catch (Exception e) {

        log.error("❌ Unexpected failure", e);
        throw new RuntimeException("Update failed", e);
    }
}





    // ---------------- ROLE ----------------
    @Override
    public void createClientRoles(String realm,
            String clientName,
            List<RoleCreationRequest> roleRequests,
            String token) {

        log.info("Creating {} roles for client '{}' in realm '{}'",
                roleRequests.size(), clientName, realm);

        String clientUUID = getClientUUID(realm, clientName, token);

        String keycloakUrl = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/clients/" + clientUUID
                + "/roles";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        WebClient webClient = WebClient.builder()
                .baseUrl(projectManagementBaseUrl)
                .build();

        Set<String> processedRoles = new HashSet<>();
        List<String> failedRoles = new ArrayList<>();

        for (RoleCreationRequest role : roleRequests) {

            String roleName = role.getName();

            if (!processedRoles.add(roleName)) {
                continue;
            }

            Map<String, Object> body = Map.of(
                    "name", roleName,
                    "description", role.getDescription());

            try {
                // ==========================
                // 1️⃣ CREATE ROLE IN KEYCLOAK
                // ==========================
                restTemplate.postForEntity(
                        keycloakUrl,
                        new HttpEntity<>(body, headers),
                        String.class);

                log.info("✅ Created role '{}' in Keycloak", roleName);

            } catch (Exception e) {

                if (e.getMessage() != null && e.getMessage().contains("409")) {
                    log.info("ℹ Role '{}' already exists in Keycloak", roleName);
                } else {
                    failedRoles.add(roleName);
                    log.error("❌ Keycloak role creation failed: {}", roleName, e);
                    continue;
                }
            }

            // ==========================
            // 2️⃣ REGISTER ROLE IN PMs
            // ==========================
            try {
                RoleRequest pmRequest = new RoleRequest();
                pmRequest.setRealmName(realm);
                pmRequest.setProductName(clientName);
                pmRequest.setRoleName(roleName);
                pmRequest.setUrls(Collections.emptyList());

                webClient.post()
                        .uri("/project/roles/save-or-update")
                        .bodyValue(pmRequest)
                        .retrieve()
                        .toBodilessEntity()
                        .block();

                log.info("📦 Role '{}' registered in Project Manager", roleName);

            } catch (Exception e) {
                // don't break role creation if PM is down
                log.warn("⚠ PM registration failed for '{}': {}", roleName, e.getMessage());
            }
        }

        if (!failedRoles.isEmpty()) {
            throw new RuntimeException(
                    "Failed to create roles: " + String.join(", ", failedRoles));
        }
    }

    // -------------------------------getClientRoles----------------------------------
    @Override
    public List<Map<String, Object>> getClientRoles(String realm, String clientName, String token) {
        log.info("Fetching client roles for client '{}' in realm '{}'", clientName, realm);

        String clientUUID = getClientUUID(realm, clientName, token);
        log.info("Client UUID for '{}' is '{}'", clientName, clientUUID);

        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/clients/" + clientUUID
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
                    List.class);

            return response.getBody();
        } catch (Exception e) {
            log.error("Failed to fetch client roles: {}", e.getMessage());
            throw new RuntimeException("Failed to fetch client roles", e);
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
    public boolean updateRole(
            String realm,
            String clientName,   // use client NAME not UUID externally
            String roleName,
            RoleCreationRequest role,
            String token) {

        log.info("Updating client role '{}' for client '{}' in realm '{}'",
                roleName, clientName, realm);

        try {
            // 1️⃣ Resolve client UUID properly (you already have this method)
            String clientUUID = getClientUUID(realm, clientName, token);

            // 2️⃣ Keycloak client role update endpoint
            String url = config.getBaseUrl()
                    + "/admin/realms/" + realm
                    + "/clients/" + clientUUID
                    + "/roles/" + roleName;

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setContentType(MediaType.APPLICATION_JSON);

            // 3️⃣ Payload (Keycloak allows renaming + description change)
            Map<String, Object> body = new HashMap<>();
            body.put("name", role.getName());                 // can rename role
            body.put("description", role.getDescription());  // update description

            HttpEntity<Map<String, Object>> entity =
                    new HttpEntity<>(body, headers);

            restTemplate.exchange(url, HttpMethod.PUT, entity, Void.class);

            log.info("✅ Role '{}' updated successfully for client '{}'",
                    roleName, clientName);

            return true;

        } catch (HttpClientErrorException.NotFound e) {
            log.error("❌ Role '{}' not found in client '{}'", roleName, clientName);
            throw new RuntimeException("Role not found: " + roleName);

        } catch (Exception e) {
            log.error("❌ Failed to update role '{}': {}", roleName, e.getMessage(), e);
            throw new RuntimeException("Failed to update role", e);
        }
    }


    @Override
    public void deleteClientRole(
            String realm,
            String clientName,
            String roleName,
            String token) {

        log.info("🗑 START deleteClientRole()");
        log.info("Realm={}, Client={}, Role={}", realm, clientName, roleName);

        try {
            // ============================
            log.info("🔍 Resolving client UUID...");
            String clientUUID = getClientUUID(realm, clientName, token);
            log.info("✅ Client UUID resolved: {}", clientUUID);

            // ============================
            String url = config.getBaseUrl()
                    + "/admin/realms/" + realm
                    + "/clients/" + clientUUID
                    + "/roles/" + roleName;

            log.info("🌐 Keycloak DELETE URL = {}", url);

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);

            log.info("📡 Sending DELETE to Keycloak...");

            ResponseEntity<Void> response = restTemplate.exchange(
                    url,
                    HttpMethod.DELETE,
                    new HttpEntity<>(headers),
                    Void.class
            );

            log.info("📬 Keycloak response status = {}", response.getStatusCode());

            if (!response.getStatusCode().is2xxSuccessful()) {
                log.error("❌ Delete refused by Keycloak");
                throw new RuntimeException("Keycloak refused delete: " + response.getStatusCode());
            }

            log.info("✅ Role successfully deleted in Keycloak");

        } catch (HttpClientErrorException.NotFound e) {
            log.error("🚫 Role not found in Keycloak");
            throw new RuntimeException("Role not found: " + roleName);

        } catch (Exception e) {
            log.error("🔥 Delete failed", e);
            throw new RuntimeException("Failed to delete client role: " + e.getMessage(), e);
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
    public void assignClientRolesByName(
            String realm,
            String username,
            String clientName,
            String token,
            List<AssignRoleRequest> roles) {

        // 1️⃣ Resolve userId from username
        String userId = resolveUserId(realm, username, token);

        // 2️⃣ Resolve client UUID from clientName
        String clientUUID = resolveClientUUID(realm, clientName, token);

        // 3️⃣ Resolve each role by name → minimal payload (id + name)
        List<Map<String, Object>> resolvedRoles = new ArrayList<>();

        for (AssignRoleRequest role : roles) {
            if (role.getName() == null || role.getName().isBlank()) {
                throw new IllegalArgumentException("Role name must not be null or empty");
            }

            Map<String, Object> resolvedRole = resolveClientRoleByName(realm, clientUUID, role.getName(), token);
            resolvedRoles.add(resolvedRole);
        }

        // 4️⃣ Assign resolved roles to user
        assignClientRolesToUser(realm, userId, clientUUID, resolvedRoles, token);

        // 5️⃣ Log cURL command for debugging
        logCurlCommand(realm, userId, clientUUID, resolvedRoles, token);

        log.info(
                "✅ Successfully assigned roles {} to user '{}' in realm '{}' for client '{}'",
                resolvedRoles.stream().map(r -> r.get("name")).toList(),
                username,
                realm,
                clientName);
    }

    private void logCurlCommand(String realm, String userId, String clientUUID,
            List<Map<String, Object>> roles, String token) {

        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/users/" + userId
                + "/role-mappings/clients/" + clientUUID;

        // Convert roles list to JSON string (pretty print optional)
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

        log.info("🔹 Equivalent cURL command to assign roles:\n{}", curl);
    }

    private String resolveClientUUID(String realm, String clientName, String token) {
        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/clients?clientId=" + clientName;

        HttpHeaders headers = authHeaders(token);

        ResponseEntity<List> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers), List.class);

        List<Map<String, Object>> clients = response.getBody();

        if (clients == null || clients.isEmpty()) {
            throw new RuntimeException("Client not found: " + clientName);
        }

        return clients.get(0).get("id").toString();
    }

    private Map<String, Object> resolveClientRoleByName(
            String realm,
            String clientUUID,
            String roleName,
            String token) {

        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/clients/" + clientUUID
                + "/roles/" + roleName;

        HttpHeaders headers = authHeaders(token);

        ResponseEntity<Map> response = restTemplate.exchange(
                url, HttpMethod.GET, new HttpEntity<>(headers), Map.class);

        Map<String, Object> role = response.getBody();

        if (role == null) {
            throw new RuntimeException("Role not found: " + roleName);
        }

        // 🔥 MINIMAL PAYLOAD (THIS IS THE KEY)
        Map<String, Object> minimalRole = new HashMap<>();
        minimalRole.put("id", role.get("id"));
        minimalRole.put("name", role.get("name"));

        return minimalRole;
    }

    private void assignClientRolesToUser(
            String realm,
            String userId,
            String clientUUID,
            List<Map<String, Object>> roles,
            String token) {

        String url = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/users/" + userId
                + "/role-mappings/clients/" + clientUUID;

        HttpHeaders headers = authHeaders(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<List<Map<String, Object>>> request = new HttpEntity<>(roles, headers);

        restTemplate.postForEntity(url, request, Void.class);

        log.info("Assigned client roles {} to user {}", roles, userId);
    }

    private HttpHeaders authHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }


//--------------------------    update assugn user to client role
@Override
public void updateUserClientRoles(
        String realm,
        String username,
        String clientName,
        List<String> newRoleNames,
        String token) {

    log.info("🚀 Updating roles {} for user '{}' in realm '{}' on client '{}'",
            newRoleNames, username, realm, clientName);

    try {

        String userId = resolveUserId(realm, username, token);
        log.info("🆔 Resolved userId = {}", userId);

        String clientUUID = getClientUUID(realm, clientName, token);
        log.info("🧩 Resolved clientUUID = {}", clientUUID);

        if (userId == null || clientUUID == null) {
            throw new RuntimeException("UserId or ClientUUID resolution failed");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);

        // 🔍 1. Fetch current roles
        String currentRolesUrl = config.getBaseUrl()
                + "/admin/realms/" + realm
                + "/users/" + userId
                + "/role-mappings/clients/" + clientUUID;

        log.info("🌐 Fetching current roles from {}", currentRolesUrl);

        ResponseEntity<List<Map<String, Object>>> currentResp =
                restTemplate.exchange(
                        currentRolesUrl,
                        HttpMethod.GET,
                        new HttpEntity<>(headers),
                        new ParameterizedTypeReference<>() {}
                );

        List<Map<String, Object>> currentRoles =
                currentResp.getBody() == null ? new ArrayList<>() : currentResp.getBody();

        log.info("📋 Current roles: {}",
                currentRoles.stream().map(r -> r.get("name")).toList());

        // 🧹 2. Remove old roles
        if (!currentRoles.isEmpty()) {

            log.info("🗑 Removing {} old roles", currentRoles.size());

            restTemplate.exchange(
                    currentRolesUrl,
                    HttpMethod.DELETE,
                    new HttpEntity<>(currentRoles, headers),
                    Void.class
            );

            log.info("🗑 Old roles removed successfully");
        } else {
            log.info("ℹ No existing roles to remove");
        }

        // ➕ 3. Fetch role representations
        List<Map<String, Object>> newRoleReps = new ArrayList<>();

        for (String roleName : newRoleNames) {

            String roleUrl = config.getBaseUrl()
                    + "/admin/realms/" + realm
                    + "/clients/" + clientUUID
                    + "/roles/" + roleName;

            log.info("📥 Fetching role '{}' from {}", roleName, roleUrl);

            ResponseEntity<Map<String, Object>> roleResp =
                    restTemplate.exchange(
                            roleUrl,
                            HttpMethod.GET,
                            new HttpEntity<>(headers),
                            new ParameterizedTypeReference<>() {}
                    );

            log.info("✅ Role '{}' loaded", roleName);

            newRoleReps.add(roleResp.getBody());
        }

        log.info("➕ Assigning {} new roles", newRoleReps.size());

        // ➕ 4. Assign new roles
        restTemplate.exchange(
                currentRolesUrl,
                HttpMethod.POST,
                new HttpEntity<>(newRoleReps, headers),
                Void.class
        );

        log.info("🎉 Roles updated successfully for user {}", username);

    } catch (HttpClientErrorException e) {

        log.error("❌ HTTP STATUS: {}", e.getStatusCode());
        log.error("❌ RESPONSE BODY: {}", e.getResponseBodyAsString());
        throw e;

    } catch (Exception e) {

        log.error("❌ Failed updating roles", e);
        throw new RuntimeException("Update roles failed: " + e.getMessage(), e);
    }
}






    // ------------------SIGNUP---------------------------

    public String createClients(String realm, String clientId, boolean isPublicClient, String token) {

        String url = config.getBaseUrl() + "/admin/realms/" + realm + "/clients";

        Map<String, Object> body = new HashMap<>();
        body.put("clientId", clientId);
        body.put("enabled", true);
        body.put("protocol", "openid-connect");

        // ✅ Always confidential (client secret)
        body.put("publicClient", false);
        body.put("clientAuthenticatorType", "client-secret");

        // ✅ Allow username/password login
        body.put("directAccessGrantsEnabled", true);

        // ✅ Enable service account (recommended)
        body.put("serviceAccountsEnabled", true);

        // 🚫 Disable browser flows (backend only)
        body.put("standardFlowEnabled", false);
        body.put("implicitFlowEnabled", false);

        // ✅ MUST be false or password grant fails silently
        body.put("bearerOnly", false);

        // 🚫 DO NOT enable unless you configure UMA
        // body.put("authorizationServicesEnabled", true);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

        ResponseEntity<String> response =
                restTemplate.exchange(url, HttpMethod.POST, entity, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to create client: " + response.getStatusCode());
        }

        return getClientUUID(realm, clientId, token);
    }

    public void increaseTokenTimingAfterRealmCreation(String realm, String masterToken) {

        Map<String, Object> tokenConfig = new HashMap<>();
        tokenConfig.put("accessTokenLifespan", 7200);
        tokenConfig.put("ssoSessionIdleTimeout", 28800);
        tokenConfig.put("ssoSessionMaxLifespan", 86400);

        webClient.put()
                .uri(config.getBaseUrl() + "/admin/realms/" + realm)
                .header("Authorization", "Bearer " + masterToken)
                .header("Content-Type", "application/json")
                .bodyValue(tokenConfig)
                .retrieve()
                .toBodilessEntity()
                .block();

        log.info("✅ Token timing updated for realm: {}", realm);
    }




    @Override
    public SignupStatus signup(String realmName, String adminPassword) {

        if (realmName == null || realmName.isBlank()) {
            throw new IllegalArgumentException("Realm name is required");
        }

        if (adminPassword == null || adminPassword.isBlank()) {
            throw new IllegalArgumentException("Admin password is required");
        }

        SignupStatus status = SignupStatus.builder()
                .status("IN_PROGRESS")
                .message("Signup started")
                .steps(new ArrayList<>())
                .build();

        String realm = realmName.trim();
        String clientId = realm + "-admin-product";
        String adminUsername = "admin";
        String adminEmail = "admin@paxarisglobal.com";
        String adminFname = "adminFirstName";
        String adminLname = "adminLastName";

        try {
            // ============================
            // Step 1 — Master token
            // ============================
            status.addStep("Get Master Token", "IN_PROGRESS", "Authenticating");
            String masterToken = getMasterToken();
            status.addStep("Get Master Token", "SUCCESS", "Token retrieved");

            // ============================
            // Step 2 — Create Realm
            // ============================
            status.addStep("Create Realm", "IN_PROGRESS", "Creating realm " + realm);
            createRealm(realm, masterToken);
            status.addStep("Create Realm", "SUCCESS", "Realm created");

            // ============================
            // Step 3 — Create Client
            // ============================
            status.addStep("Create Client", "IN_PROGRESS", "Creating client " + clientId);

            String clientUUID = createClients(
                    realm,
                    clientId,
                    false,          // private client (admin product)
                    masterToken
            );

            status.addStep("Create Client", "SUCCESS", "Client created: " + clientUUID);

            // ============================
            // Step 4 — Create Admin User
            // ============================
            status.addStep("Create Admin User", "IN_PROGRESS", "Creating admin user");

            Map<String, Object> userPayload = new HashMap<>();
            userPayload.put("username", adminUsername);
            userPayload.put("email", adminEmail);
            userPayload.put("firstName", adminFname);
            userPayload.put("lastName", adminLname);
            userPayload.put("enabled", true);
            userPayload.put("emailVerified", true);
            userPayload.put("requiredActions", Collections.emptyList());

            Map<String, Object> credentials = Map.of(
                    "type", "password",
                    "value", adminPassword,
                    "temporary", false
            );

            userPayload.put("credentials", List.of(credentials));

            String userId = createUser(realm, masterToken, userPayload);

            status.addStep("Create Admin User", "SUCCESS", "Admin user created");

            // ============================
            // Step 5 — Assign Admin Roles
            // ============================
            status.addStep("Assign Roles", "IN_PROGRESS", "Assigning admin permissions");

            List<String> adminRoles = List.of(
                    "create-client",
                    "impersonation",
                    "manage-realm",
                    "manage-users",
                    "manage-clients"
            );

            for (String role : adminRoles) {
                assignRealmManagementRoleToUser(realm, userId, role, masterToken);
            }

            status.addStep("Assign Roles", "SUCCESS", "Admin roles assigned");

            increaseTokenTimingAfterRealmCreation(realm, masterToken);


            // ============================
            // Done
            // ============================
            status.setStatus("SUCCESS");
            status.setMessage("Signup completed successfully");

            return status;

        } catch (Exception e) {
            log.error("Signup failed for realm '{}'", realm, e);

            status.setStatus("FAILED");
            status.setMessage("Signup failed: " + e.getMessage());

            return status;
        }
    }

    // ------------------SIGNUP end---------------------------
    // ------------------SIGNUP end---------------------------

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
