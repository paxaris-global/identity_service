package com.paxaris.identity_service.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.paxaris.identity_service.dto.*;
import com.paxaris.identity_service.service.KeycloakProductService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;
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
 * - Product Management: Product creation with GitHub provisioning
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

    private static final String GRANT_TYPE_PASSWORD = "password";
    private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

    private final KeycloakConfig config;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final WebClient webClient;

    @Value("${project.management.base-url}")
    private String projectManagementBaseUrl;

    @Value("${project.management.role-sync-path}")
    private String roleSyncPath;

    @Value("${project.management.provision-upload-path}")
    private String provisionUploadPath;

    @Value("${project.management.product-provision-path}")
    private String productProvisionPath;

    @Value("${project.management.product-urls-path}")
    private String productUrlsPath;

    @Value("${project.management.product-deployment-status-path}")
    private String productDeploymentStatusPath;

    @Value("${keycloak.client-id}")
    private String adminCliClient;

    @Value("${keycloak.master-realm}")
    private String masterRealm;

    @Value("${keycloak.realm-management-client}")
    private String realmManagementClient;

    @Value("${keycloak.protocol}")
    private String keycloakProtocol;

    @Value("${identity.default-admin.username}")
    private String defaultAdminUsername;

    @Value("${identity.default-admin.email}")
    private String defaultAdminEmail;

    @Value("${identity.default-admin.first-name}")
    private String defaultAdminFirstName;

    @Value("${identity.default-admin.last-name}")
    private String defaultAdminLastName;

    @Value("${identity.default-admin.realm-management-roles}")
    private String defaultAdminRealmManagementRoles;

    @Value("${identity.token-config.access-token-lifespan-seconds}")
    private int accessTokenLifespanSeconds;

    @Value("${identity.token-config.sso-session-idle-timeout-seconds}")
    private int ssoSessionIdleTimeoutSeconds;

    @Value("${identity.token-config.sso-session-max-lifespan-seconds}")
    private int ssoSessionMaxLifespanSeconds;

    @Value("${identity.frontend.allowed-origins}")
    private String frontendAllowedOrigins;


    // ==================== TOKEN MANAGEMENT ====================

    private String getMasterToken() {
        log.debug("Fetching master admin token from Keycloak");
        String tokenUrl = buildUrl("/realms/" + masterRealm + "/protocol/openid-connect/token");
        MultiValueMap<String, String> body = buildTokenRequestBody(
            GRANT_TYPE_PASSWORD, adminCliClient, config.getAdminUsername(), config.getAdminPassword(), null);

        try {
            Map<String, Object> response = executeTokenRequest(tokenUrl, body);
            String token = (String) response.get("access_token");
            log.debug("Master token retrieved successfully");
            return token;
        } catch (HttpClientErrorException.Unauthorized e) {
            log.error("Master token auth failed - Username: {}, Client: {}. Check Keycloak credentials.",
                config.getAdminUsername(), adminCliClient);
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
    public Map<String, Object> getRealmToken(String realm, String username, String password,String clientId, String clientSecret) {

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
        log.debug("Starting login flow for user '{}' in realm '{}' with product '{}'", username, realm, clientId);

        try {
            if (!adminCliClient.equals(clientId)) {
                ensureLoginClientAllowsPasswordGrant(realm, clientId);
            }
            String clientSecret = null;
            if (!adminCliClient.equals(clientId)) {
                clientSecret = fetchProductSecretByClientId(realm, clientId);
                log.debug("Product secret resolved for product '{}'", clientId);
                if (clientSecret == null || clientSecret.isBlank()) {
                    String masterToken = getMasterToken();
                    if (clientRequiresSecret(realm, clientId, masterToken)) {
                        throw new IllegalStateException(
                            "Keycloak client '"
                                + clientId
                                + "' is confidential but has no client_secret in Keycloak. "
                                + "Open Keycloak Admin → Clients → "
                                + clientId
                                + " → Credentials (regenerate if needed). "
                                + "The identity service uses this secret for the password grant.");
                    }
                }
            }

            try {
                return postPasswordGrantToken(realm, clientId, username, password, clientSecret);
            } catch (HttpStatusCodeException first) {
                if (!first.getStatusCode().is4xxClientError()) {
                    throw first;
                }
                if (!adminCliClient.equals(clientId) && shouldRetryLoginAfterKeycloakClientFix(first)) {
                    log.warn("Login token rejected ({}); re-applying Keycloak client settings and retrying once", first.getStatusCode());
                    ensureLoginClientAllowsPasswordGrant(realm, clientId);
                    clientSecret = fetchProductSecretByClientId(realm, clientId);
                    return postPasswordGrantToken(realm, clientId, username, password, clientSecret);
                }
                throw first;
            }
        } catch (HttpStatusCodeException e) {
            if (e.getStatusCode().is5xxServerError()) {
                String body = e.getResponseBodyAsString();
                log.error("Keycloak returned {} for realm '{}': {}", e.getStatusCode(), realm, body);
                throw new IllegalStateException(
                    "Keycloak error (" + e.getStatusCode().value() + "). Check Keycloak logs.",
                    e);
            }
            String body = e.getResponseBodyAsString();
            String parsed = parseKeycloakOAuthError(body);
            log.warn("Keycloak password grant failed for realm '{}' user '{}': {} — {}", realm, username, e.getStatusCode(), body);
            throw new IllegalArgumentException(parsed != null ? parsed : "Keycloak rejected login (" + e.getStatusCode() + ")");
        } catch (ResourceAccessException e) {
            log.error("Cannot reach Keycloak at {} — {}", config.getBaseUrl(), e.toString());
            throw new IllegalStateException(
                "Cannot reach Keycloak at "
                    + config.getBaseUrl()
                    + ". Set KEYCLOAK_BASE_URL to your Keycloak base URL (e.g. http://127.0.0.1:8080) and ensure it is reachable from identity-service.",
                e);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to get realm token for user '{}': {}", username, e.getMessage(), e);
            throw new RuntimeException("Failed to get realm token: " + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
        }
    }

    private Map<String, Object> postPasswordGrantToken(
        String realm,
        String clientId,
        String username,
        String password,
        String clientSecret
    ) throws Exception {
        String tokenUrl = buildUrl("/realms/" + realm + "/protocol/openid-connect/token");
        MultiValueMap<String, String> formData =
            buildTokenRequestBody(GRANT_TYPE_PASSWORD, clientId, username, password, clientSecret);
        HttpHeaders headers = createFormHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(formData, headers);
        ResponseEntity<String> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, request, String.class);
        return objectMapper.readValue(response.getBody(), new TypeReference<>() {});
    }

    /**
     * Retry only when fixing Keycloak client flags (e.g. Direct Access Grants) or fetching a new secret can help.
     * Do not retry on {@code invalid_grant} from wrong username/password — Keycloak uses that error too and retry is misleading.
     */
    private boolean shouldRetryLoginAfterKeycloakClientFix(HttpStatusCodeException e) {
        if (!e.getStatusCode().is4xxClientError()) {
            return false;
        }
        String body = e.getResponseBodyAsString();
        if (body == null || body.isBlank()) {
            return e.getStatusCode() == HttpStatus.UNAUTHORIZED || e.getStatusCode() == HttpStatus.BAD_REQUEST;
        }
        String lower = body.toLowerCase(Locale.ROOT);
        if (lower.contains("invalid user credentials")
            || lower.contains("invalid_username_or_password")
            || lower.contains("account disabled")) {
            return false;
        }
        // Wrong password and most grant failures use invalid_grant — retrying client settings does not help.
        if (lower.contains("invalid_grant")) {
            return false;
        }
        return lower.contains("unauthorized_client")
            || lower.contains("invalid_client")
            || lower.contains("not_allowed")
            || lower.contains("client not allowed")
            || lower.contains("direct access");
    }

    /** {@code true} if Keycloak client is confidential (needs {@code client_secret} on token endpoint). */
    private boolean clientRequiresSecret(String realm, String clientId, String adminToken) {
        try {
            String uuid = getProductUUID(realm, clientId, adminToken);
            String url = buildUrl("/admin/realms/" + realm + "/clients/" + uuid);
            ResponseEntity<String> getResp =
                restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(createBearerHeaders(adminToken)), String.class);
            Map<String, Object> client = objectMapper.readValue(getResp.getBody(), new TypeReference<>() {});
            return !Boolean.TRUE.equals(client.get("publicClient"));
        } catch (Exception ex) {
            log.warn("Could not read publicClient flag for '{}': {} — assuming secret may be required", clientId, ex.getMessage());
            return false;
        }
    }

    /**
     * Parses Keycloak / OAuth2 error JSON: {"error":"...","error_description":"..."}
     */
    private String parseKeycloakOAuthError(String jsonBody) {
        if (jsonBody == null || jsonBody.isBlank()) {
            return null;
        }
        try {
            Map<String, Object> m = objectMapper.readValue(jsonBody, new TypeReference<>() {});
            Object desc = m.get("error_description");
            if (desc instanceof String s && !s.isBlank()) {
                return s.trim();
            }
            Object err = m.get("error");
            if (err instanceof String s && !s.isBlank()) {
                return s.trim();
            }
        } catch (Exception ignored) {
            // fall through
        }
        return null;
    }

    @Override
    public Map<String, Object> refreshMyRealmToken(String refreshToken, String clientId, String realm) {
        log.debug("Refreshing token for realm '{}' and product '{}'", realm, clientId);

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("Refresh token is required");
        }

        try {
            if (!adminCliClient.equals(clientId)) {
                ensureLoginClientAllowsPasswordGrant(realm, clientId);
            }
            String clientSecret = null;
            if (!adminCliClient.equals(clientId)) {
                clientSecret = fetchProductSecretByClientId(realm, clientId);
            }

            String tokenUrl = buildUrl("/realms/" + realm + "/protocol/openid-connect/token");
            MultiValueMap<String, String> body =
                buildRefreshTokenRequestBody(clientId, refreshToken, clientSecret);

            return executeTokenRequest(tokenUrl, body);
        } catch (HttpClientErrorException e) {
            log.warn(
                "Refresh token request failed for realm '{}' and product '{}': {}",
                realm,
                clientId,
                e.getResponseBodyAsString()
            );
            throw new RuntimeException("Refresh token failed: " + e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            log.error("Failed to refresh token for realm '{}' and product '{}': {}", realm, clientId, e.getMessage());
            throw new RuntimeException("Failed to refresh token", e);
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
                if (redirectUris != null && !redirectUris.isEmpty()) {
                    String first = redirectUris.get(0);
                    if (first != null && first.endsWith("/*")) {
                        return first.substring(0, first.length() - 2);
                    }
                    return first;
                }
                log.warn("No redirect URIs configured for client '{}' — using SPA default path", clientId);
                return "/dashboard/product";
            }
            return "/dashboard/product";
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


    // ==================== PRODUCT MANAGEMENT ====================

    @Override
    public SignupStatus createProductInKeycloak(
            String realm,
            String clientId,
            boolean isPublicClient,
            SignupStatus status
    ) {
        try {
            status.addStep(
                    "Create Product in Keycloak",
                    "IN_PROGRESS",
                    "Reserving product URLs and creating Keycloak client"
            );

            Map<String, Object> urlAllocation = allocateProductUrlsViaProductManager(realm, clientId);
            String frontendBaseUrl = requireString(urlAllocation, "frontendBaseUrl");
            String backendBaseUrl = requireString(urlAllocation, "backendBaseUrl");

            String clientUUID = createKeycloakClientWithRetry(realm, clientId, isPublicClient, frontendBaseUrl);

            status.addStep(
                    "Create Product in Keycloak",
                    "SUCCESS",
                    "Keycloak client '" + clientId + "' ready (id=" + clientUUID + ")"
            );

            status.setStatus("KEYCLOAK_SUCCESS");
            status.setMessage("Keycloak product created successfully. Deployment can proceed.");
            status.setToken(Map.of(
                    "clientUUID", clientUUID,
                    "frontendBaseUrl", frontendBaseUrl,
                    "backendBaseUrl", backendBaseUrl,
                    "frontendNodePort", urlAllocation.get("frontendNodePort"),
                    "backendNodePort", urlAllocation.get("backendNodePort")
            ));
            return status;
        } catch (Exception e) {
            log.error("Keycloak product creation failed for realm '{}', product '{}': {}", realm, clientId, e.getMessage());
            handleProvisioningFailure(status, e);
            failStep(status, "Create Product in Keycloak", e.getMessage());
            throw new RuntimeException("Keycloak product creation failed: " + e.getMessage(), e);
        }
    }

    @Override
    public String deployProduct(
            String realm,
            String clientId,
            MultipartFile backendZip,
            MultipartFile frontendZip,
            SignupStatus status,
            String ownerUsername
    ) {
        Path backendPath = null;
        Path frontendPath = null;
        Map<String, Object> provisioningResult = null;
        String frontendBaseUrl = null;
        String backendBaseUrl = null;

        try {
            verifyKeycloakProductExists(realm, clientId);

            if (status.getToken() != null) {
                Object fe = status.getToken().get("frontendBaseUrl");
                Object be = status.getToken().get("backendBaseUrl");
                if (fe != null) {
                    frontendBaseUrl = fe.toString();
                }
                if (be != null) {
                    backendBaseUrl = be.toString();
                }
            }
            if (frontendBaseUrl == null || frontendBaseUrl.isBlank()) {
                Map<String, Object> urlAllocation = allocateProductUrlsViaProductManager(realm, clientId);
                frontendBaseUrl = requireString(urlAllocation, "frontendBaseUrl");
                backendBaseUrl = requireString(urlAllocation, "backendBaseUrl");
            }

            status.addStep("Extract Application Code", "IN_PROGRESS", "Extracting ZIP files");
            backendPath = Files.createTempDirectory("backend-extract-");
            frontendPath = Files.createTempDirectory("frontend-extract-");
            extractZipFile(backendZip, backendPath);
            extractZipFile(frontendZip, frontendPath);
            status.addStep("Extract Application Code", "SUCCESS", "ZIP files extracted");

            String backendRepo = generateRepositoryName(realm, ownerUsername, clientId + "-backend");
            String frontendRepo = generateRepositoryName(realm, ownerUsername, clientId + "-frontend");
            status.addStep("Generate Repository Names", "SUCCESS", backendRepo + " & " + frontendRepo);

            Path backendSourcePath = resolveProvisioningSourceRoot(backendPath);
            Path frontendSourcePath = resolveProvisioningSourceRoot(frontendPath);

            status.addStep("Provision GitHub Repositories", "IN_PROGRESS", "Creating repos, uploading code, and updating GitOps");
            status.addStep("Generate Kubernetes Manifests", "IN_PROGRESS", "Postgres, Redis, backend, and frontend manifests");
            status.addStep("Sync ArgoCD Applications", "IN_PROGRESS", "Registering ArgoCD apps and syncing cluster");
            provisioningResult = provisionProductViaProductManager(
                    realm,
                    clientId,
                    backendRepo,
                    frontendRepo,
                    backendSourcePath,
                    frontendSourcePath
            );
            status.addStep("Provision GitHub Repositories", "SUCCESS", "GitHub repositories provisioned");
            status.addStep("Generate Kubernetes Manifests", "SUCCESS", "Kubernetes manifests pushed to Paxo GitOps");
            status.addStep(
                    "Sync ArgoCD Applications",
                    "SUCCESS",
                    "ArgoCD applications created. Frontend: " + frontendBaseUrl + ", Backend: " + backendBaseUrl
            );
            cleanupDirectory(backendPath);
            cleanupDirectory(frontendPath);

            status.setStatus("SUCCESS");
            status.setMessage("Product provisioning completed successfully. Open product at: " + frontendBaseUrl);
            status.setToken(Map.of(
                    "frontendBaseUrl", frontendBaseUrl,
                    "backendBaseUrl", backendBaseUrl,
                    "frontendNodePort", provisioningResult.get("frontendNodePort"),
                    "backendNodePort", provisioningResult.get("backendNodePort")
            ));
            return clientId;
        } catch (Exception e) {
            log.error("Product deployment failed for realm '{}', product '{}': {}", realm, clientId, e.getMessage());
            handleProvisioningFailure(status, e);
            cleanupDirectory(backendPath);
            cleanupDirectory(frontendPath);
            throw new RuntimeException(
                    "Keycloak client exists but deployment failed: " + e.getMessage(),
                    e
            );
        }
    }

    @Override
    public String createProduct(String realm, String clientId, boolean isPublicClient, String adminToken,
            MultipartFile backendZip, MultipartFile frontendZip,
            SignupStatus status, String ownerUsername) {
        createProductInKeycloak(realm, clientId, isPublicClient, status);
        return deployProduct(realm, clientId, backendZip, frontendZip, status, ownerUsername);
    }

    @Override
    public Map<String, Object> getProductDeploymentStatus(String realm, String productId) {
        String statusUrl = projectManagementBaseUrl + productDeploymentStatusPath
                + "/" + realm + "/" + productId + "/status";
        try {
            ResponseEntity<Map> response = restTemplate.getForEntity(statusUrl, Map.class);
            if (response.getBody() == null) {
                throw new RuntimeException("Product Manager returned empty deployment status");
            }
            return response.getBody();
        } catch (HttpStatusCodeException e) {
            throw new RuntimeException(
                    "Failed to fetch deployment status: HTTP " + e.getStatusCode().value(),
                    e
            );
        } catch (ResourceAccessException e) {
            throw new RuntimeException("Product Manager is unreachable while fetching deployment status", e);
        }
    }

    private void verifyKeycloakProductExists(String realm, String clientId) {
        String token = getMasterToken();
        try {
            getProductUUID(realm, clientId, token);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Keycloak client '" + clientId + "' does not exist in realm '" + realm
                            + "'. Create the product in Keycloak before deployment.",
                    e
            );
        }
    }

    private void failStep(SignupStatus status, String stepName, String error) {
        for (SignupStatus.StepStatus step : status.getSteps()) {
            if (stepName.equals(step.getStepName()) && "IN_PROGRESS".equals(step.getStatus())) {
                step.setStatus("FAILED");
                step.setError(error);
                return;
            }
        }
    }

    private String createKeycloakClientWithRetry(
            String realm,
            String clientId,
            boolean isPublicClient,
            String frontendBaseUrl
    ) {
        try {
            return createKeycloakClient(realm, clientId, isPublicClient, frontendBaseUrl, getMasterToken());
        } catch (HttpClientErrorException.Unauthorized e) {
            log.warn("Keycloak admin token rejected while creating '{}', retrying once", clientId);
            return createKeycloakClient(realm, clientId, isPublicClient, frontendBaseUrl, getMasterToken());
        }
    }

    private String createKeycloakClient(String realm, String clientId, boolean isPublicClient,
                                        String frontendBaseUrl, String token) {
        log.info("Creating Keycloak product '{}' in realm '{}' (public={})", clientId, realm, isPublicClient);
        String url = buildUrl("/admin/realms/" + realm + "/clients");
        Map<String, Object> body = buildClientConfiguration(clientId, isPublicClient, frontendBaseUrl);
        HttpHeaders headers = createJsonHeaders(token);

        try {
            restTemplate.exchange(url, HttpMethod.POST, new HttpEntity<>(body, headers), Void.class);
            String clientUUID = getProductUUID(realm, clientId, token);
            if (!isPublicClient) {
                ensureClientSecret(realm, clientUUID, token);
            }
            log.info("Product '{}' created successfully with UUID: {}", clientId, clientUUID);
            return clientUUID;
        } catch (HttpClientErrorException.Conflict e) {
            log.warn("Product '{}' already exists in realm '{}': {}", clientId, realm, e.getResponseBodyAsString());
            String clientUUID = getProductUUID(realm, clientId, token);
            updateKeycloakClient(realm, clientUUID, buildClientConfiguration(clientId, isPublicClient, frontendBaseUrl), token);
            if (!isPublicClient) {
                ensureClientSecret(realm, clientUUID, token);
            }
            return clientUUID;
        } catch (HttpClientErrorException.Unauthorized e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to create product '{}': {}", clientId, e.getMessage());
            throw new RuntimeException("Failed to create product", e);
        }
    }

    private Map<String, Object> buildClientConfiguration(String clientId, boolean isPublicClient, String frontendBaseUrl) {
        Map<String, Object> config = new HashMap<>();
        config.put("clientId", clientId);
        config.put("enabled", true);
        config.put("protocol", keycloakProtocol);
        config.put("redirectUris", List.of(frontendBaseUrl + "/*"));
        config.put("webOrigins", List.of(frontendBaseUrl));
        config.put("rootUrl", frontendBaseUrl);
        config.put("baseUrl", frontendBaseUrl);
        config.put("attributes", Map.of("post.logout.redirect.uris", frontendBaseUrl + "/*"));

        if (isPublicClient) {
            config.put("publicClient", true);
            config.put("standardFlowEnabled", true);
            // Password grant (used by identity-service login proxy) requires Direct Access Grants in Keycloak.
            config.put("directAccessGrantsEnabled", true);
            config.put("serviceAccountsEnabled", false);
            config.put("implicitFlowEnabled", false);
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

    private void updateKeycloakClient(String realm, String clientUUID, Map<String, Object> body, String token) {
        String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID);
        HttpHeaders headers = createJsonHeaders(token);
        restTemplate.exchange(url, HttpMethod.PUT, new HttpEntity<>(body, headers), Void.class);
        log.info("Product '{}' updated successfully with generated frontend URL", body.get("clientId"));
    }

    private void ensureClientSecret(String realm, String clientUUID, String token) {
        log.debug("Generating product secret for UUID: {}", clientUUID);
        String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID + "/client-secret");
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url, HttpMethod.POST, new HttpEntity<>(headers), new ParameterizedTypeReference<>() {});
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("Failed to generate product secret");
            }
            log.debug("Product secret generated successfully for UUID: {}", clientUUID);
        } catch (Exception e) {
            log.error("Failed to generate product secret: {}", e.getMessage());
            throw new RuntimeException("Failed to generate product secret", e);
        }
    }

    @Override
    public List<Map<String, Object>> getAllProducts(String realm, String token) {
        log.info("Fetching all products in realm '{}'", realm);
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
        log.debug("Fetching product secret for product '{}' in realm '{}'", clientId, realm);
        String clientUUID = getProductUUID(realm, clientId, token);
        String url = buildUrl("/admin/realms/" + realm + "/clients/" + clientUUID + "/client-secret");
        HttpHeaders headers = createBearerHeaders(token);

        try {
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            Map<String, Object> map = objectMapper.readValue(response.getBody(), new TypeReference<>() {});
            Object raw = map.get("value");
            if (!(raw instanceof String s) || s.isBlank()) {
                return null;
            }
            return s;
        } catch (HttpClientErrorException e) {
            // Public OIDC clients have no client secret; Keycloak Admin API returns 404 for this resource.
            if (e.getStatusCode().value() == 404) {
                log.debug("No client secret for '{}' in realm '{}' (public client or not generated)", clientId, realm);
                return null;
            }
            log.error("Failed to fetch secret for '{}': {}", clientId, e.getMessage());
            throw new RuntimeException("Failed to fetch product secret", e);
        } catch (Exception e) {
            log.error("Failed to fetch secret for '{}': {}", clientId, e.getMessage());
            throw new RuntimeException("Failed to fetch product secret", e);
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

            List<Map<String, Object>> products = response.getBody();
            if (products != null && !products.isEmpty()) {
                String uuid = (String) products.get(0).get("id");
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
        log.debug("Fetching product secret for product '{}' in realm '{}'", clientId, realm);
        try {
            String adminToken = getMasterToken();
            return getProductSecret(realm, clientId, adminToken);
        } catch (Exception e) {
            log.error("Failed to fetch product secret for '{}': {}", clientId, e.getMessage());
            throw new RuntimeException("Failed to fetch product secret for product " + clientId, e);
        }
    }

    /**
     * Keycloak returns 401 on the password grant if {@code directAccessGrantsEnabled} is false.
     * Older realms or manual edits may leave that disabled; merge configured local dev redirect URIs so
     * browsers using the current Paxo frontend port match Keycloak origins.
     */
    private void ensureLoginClientAllowsPasswordGrant(String realm, String clientId) {
        String adminToken = getMasterToken();
        String uuid = getProductUUID(realm, clientId, adminToken);
        String url = buildUrl("/admin/realms/" + realm + "/clients/" + uuid);
        ResponseEntity<String> getResp =
            restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(createBearerHeaders(adminToken)), String.class);
        Map<String, Object> client;
        try {
            client = objectMapper.readValue(getResp.getBody(), new TypeReference<>() {});
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Keycloak client JSON for '" + clientId + "' in realm '" + realm + "' was not valid", e);
        }

        boolean needsUpdate = false;
        if (!Boolean.TRUE.equals(client.get("directAccessGrantsEnabled"))) {
            client.put("directAccessGrantsEnabled", true);
            needsUpdate = true;
            log.info("Enabling directAccessGrants for Keycloak client '{}' in realm '{}'", clientId, realm);
        }
        needsUpdate |= mergeLocalDevClientUrls(client);

        if (needsUpdate) {
            try {
                restTemplate.exchange(url, HttpMethod.PUT, new HttpEntity<>(client, createJsonHeaders(adminToken)), Void.class);
                log.info("Updated Keycloak client '{}' in realm '{}' for SPA login (password grant / redirects)", clientId, realm);
            } catch (Exception e) {
                log.error("PUT Keycloak client '{}' in realm '{}' failed: {}", clientId, realm, e.getMessage());
                throw new IllegalStateException(
                    "Could not update Keycloak client '" + clientId + "' (enable Direct Access Grants). Admin API error: " + e.getMessage(),
                    e);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private boolean mergeLocalDevClientUrls(Map<String, Object> client) {
        boolean changed = false;
        List<String> webOrigins = frontendWebOrigins();
        changed |= mergeUriList(client, "redirectUris", frontendRedirectUris(webOrigins));
        changed |= mergeUriList(client, "webOrigins", webOrigins);
        return changed;
    }

    private List<String> frontendWebOrigins() {
        List<String> origins = Arrays.stream(frontendAllowedOrigins.split(","))
            .map(String::trim)
            .filter(origin -> !origin.isEmpty())
            .distinct()
            .toList();
        if (!origins.isEmpty()) {
            return origins;
        }
        return List.of("http://127.0.0.1:4200", "http://localhost:4200");
    }

    private List<String> frontendRedirectUris(List<String> webOrigins) {
        return webOrigins.stream()
            .map(origin -> origin.endsWith("/*") ? origin : origin + "/*")
            .toList();
    }

    @SuppressWarnings("unchecked")
    private boolean mergeUriList(Map<String, Object> client, String key, List<String> defaults) {
        List<String> list = (List<String>) client.get(key);
        if (list == null) {
            list = new ArrayList<>();
        } else {
            list = new ArrayList<>(list);
        }
        boolean changed = false;
        for (String add : defaults) {
            if (!list.contains(add)) {
                list.add(add);
                changed = true;
            }
        }
        if (changed) {
            client.put(key, list);
        }
        return changed;
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
        } catch (HttpClientErrorException.Conflict e) {
            log.warn("User '{}' already exists in realm '{}'; reusing existing user", username, realm);
            return resolveUserId(realm, username, token);
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
            WebClient pmWebClient = webClient.mutate().baseUrl(projectManagementBaseUrl).build();
            RoleRequest pmRequest = new RoleRequest();
            pmRequest.setRealmName(realm);
            pmRequest.setProductName(clientId);
            pmRequest.setRoleName(role.getName());
            pmRequest.setUri(role.getUri());
            pmRequest.setHttpMethod(role.getHttpMethod());

            pmWebClient.post()
                .uri(roleSyncPath)
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
        } catch (HttpClientErrorException.Conflict e) {
            log.info("Role '{}' already exists in product UUID '{}' in realm '{}'", role.getName(), clientUUID, realm);
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
        String url = buildUrl("/admin/realms/" + realm + "/clients?clientId=" + realmManagementClient);
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
            String clientUUID = executeCreateClientStep(status, realm, clientId, masterToken);

            // Ensure all major admin roles exist for the admin product/client before assigning
            String[] adminRoles = new String[] {
                "admin-management",
                "manage-realm",
                "manage-users",
                "manage-clients",
                "create-client",
                "impersonation"
            };
            for (String roleName : adminRoles) {
                RoleCreationRequest role = new RoleCreationRequest();
                role.setName(roleName);
                role.setDescription(roleName + " role for product");
                createRole(realm, clientUUID, role, masterToken);
            }

            // Ensure all major admin roles exist for the realm-management client before assignment
            String realmManagementClientId = getRealmManagementClientId(realm, masterToken);
            for (String roleName : adminRoles) {
                RoleCreationRequest role = new RoleCreationRequest();
                role.setName(roleName);
                role.setDescription(roleName + " role for realm management");
                createRole(realm, realmManagementClientId, role, masterToken);
            }

            String userId = executeCreateAdminUserStep(status, realm, adminPassword, masterToken);
            executeAssignAdminRolesStep(status, realm, userId, masterToken);

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
        status.addStep("Create Product", "IN_PROGRESS", "Creating admin product " + clientId);
        String clientUUID = createAdminClient(realm, clientId, token);
        status.addStep("Create Product", "SUCCESS", "Product created: " + clientUUID);
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
        status.addStep("Assign Roles", "IN_PROGRESS", "Assigning all admin roles");
        String[] adminRoles = new String[] {
            "admin-management",
            "manage-realm",
            "manage-users",
            "manage-clients",
            "create-client",
            "impersonation"
        };
        for (String roleName : adminRoles) {
            assignRealmManagementRoleToUser(realm, userId, roleName, token);
        }
        status.addStep("Assign Roles", "SUCCESS", "All admin roles assigned");
    }

    private Map<String, Object> buildAdminUserPayload(String adminPassword) {
        Map<String, Object> userPayload = new HashMap<>();
        userPayload.put("username", defaultAdminUsername);
        userPayload.put("email", defaultAdminEmail);
        userPayload.put("firstName", defaultAdminFirstName);
        userPayload.put("lastName", defaultAdminLastName);
        userPayload.put("enabled", true);
        userPayload.put("emailVerified", true);
        userPayload.put("requiredActions", Collections.emptyList());
        userPayload.put("credentials", List.of(Map.of("type", "password", "value", adminPassword, "temporary", false)));
        return userPayload;
    }

    private String createAdminClient(String realm, String clientId, String token) {
        log.debug("Creating admin product '{}' in realm '{}'", clientId, realm);
        String url = buildUrl("/admin/realms/" + realm + "/clients");
        Map<String, Object> body = new HashMap<>();
        body.put("clientId", clientId);
        body.put("enabled", true);
        body.put("protocol", keycloakProtocol);
        body.put("publicClient", false);
        body.put("clientAuthenticatorType", "client-secret");
        body.put("directAccessGrantsEnabled", true);
        body.put("serviceAccountsEnabled", true);
        body.put("standardFlowEnabled", false);
        body.put("implicitFlowEnabled", false);
        body.put("bearerOnly", false);
        // Required for SPA login behind port-forward / ngrok; avoids empty redirectUris (bad redirects / browser blocks).
        List<String> webOrigins = frontendWebOrigins();
        body.put("redirectUris", frontendRedirectUris(webOrigins));
        body.put("webOrigins", webOrigins);
        body.put("rootUrl", webOrigins.get(0));
        body.put("baseUrl", "/");

        HttpHeaders headers = createJsonHeaders(token);

        try {
            restTemplate.exchange(url, HttpMethod.POST, new HttpEntity<>(body, headers), Void.class);
            String clientUUID = getProductUUID(realm, clientId, token);
            ensureClientSecret(realm, clientUUID, token);
            log.info("Admin product '{}' created successfully with UUID: {}", clientId, clientUUID);
            return clientUUID;
        } catch (HttpClientErrorException.Conflict e) {
            log.warn("Admin product '{}' already exists in realm '{}'; reusing existing client", clientId, realm);
            String clientUUID = getProductUUID(realm, clientId, token);
            ensureLoginClientAllowsPasswordGrant(realm, clientId);
            if (getProductSecret(realm, clientId, token) == null) {
                ensureClientSecret(realm, clientUUID, token);
            }
            return clientUUID;
        } catch (Exception e) {
            log.error("Failed to create admin product: {}", e.getMessage());
            throw new RuntimeException("Failed to create admin product", e);
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

    private MultiValueMap<String, String> buildRefreshTokenRequestBody(
        String clientId,
        String refreshToken,
        String clientSecret
    ) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", GRANT_TYPE_REFRESH_TOKEN);
        body.add("client_id", clientId);
        if (clientSecret != null && !clientSecret.isBlank()) {
            body.add("client_secret", clientSecret);
        }
        body.add("refresh_token", refreshToken);
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

    private Path resolveProvisioningSourceRoot(Path extractedRoot) throws IOException {
        try (var children = Files.list(extractedRoot)) {
            List<Path> entries = children.toList();
            List<Path> directories = entries.stream().filter(Files::isDirectory).toList();
            boolean hasTopLevelFiles = entries.stream().anyMatch(Files::isRegularFile);

            if (!hasTopLevelFiles && directories.size() == 1) {
                Path nestedRoot = directories.get(0);
                log.info("Using nested ZIP root '{}' as provisioning source", nestedRoot.getFileName());
                return nestedRoot;
            }
        }

        return extractedRoot;
    }

    // GitHub upload methods removed - now delegated to Product Manager service

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

    // ==================== PROVISIONING (via Product Manager) ====================

    /**
     * Generate a standardized repository name from realm, user, and product name
     */
    private String generateRepositoryName(String realmName, String adminUsername, String productName) {
        String adminPart = (adminUsername != null && !adminUsername.isBlank()) ? adminUsername : defaultAdminUsername;
        String rawName = String.format("%s-%s-%s", realmName, adminPart, productName).toLowerCase();

        // GitHub/Docker-friendly kebab-case: remove underscores and collapse separators.
        return rawName
                .replace('_', '-')
                .replaceAll("[^a-z0-9-]", "-")
                .replaceAll("-+", "-")
                .replaceAll("^-+", "")
                .replaceAll("-+$", "");
    }

    /**
     * Call Product Manager microservice to provision repository with uploaded code
     */
    private Map<String, Object> provisionProductViaProductManager(
            String realmName,
            String productId,
            String backendRepoName,
            String frontendRepoName,
            Path backendCodePath,
            Path frontendCodePath
    ) throws IOException {
        String provisionUrl = projectManagementBaseUrl + productProvisionPath;

        log.info("Provisioning product '{}' via Product Manager at {}", productId, provisionUrl);

        Path backendZipFile = null;
        Path frontendZipFile = null;
        try {
            backendZipFile = createZipFromDirectory(backendCodePath);
            frontendZipFile = createZipFromDirectory(frontendCodePath);

            return callProductManagerProductProvisioning(
                    provisionUrl,
                    realmName,
                    productId,
                    backendRepoName,
                    frontendRepoName,
                    backendZipFile,
                    frontendZipFile
            );
        } catch (Exception e) {
            log.error("❌ Failed to provision product via Product Manager: {}", e.getMessage());
            throw new RuntimeException("Product Manager provisioning failed for product: " + productId, e);
        } finally {
            cleanupTempFile(backendZipFile);
            cleanupTempFile(frontendZipFile);
        }
    }

    private Map<String, Object> allocateProductUrlsViaProductManager(String realmName, String productId) throws IOException {
        String allocateUrl = projectManagementBaseUrl + productUrlsPath;
        log.info("Allocating product URLs for '{}' via Product Manager at {}", productId, allocateUrl);

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("realmName", realmName);
            body.add("productId", productId);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(allocateUrl, request, Map.class);

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                throw new RuntimeException("Product Manager URL allocation returned HTTP " + response.getStatusCode().value());
            }
            Map<String, Object> responseBody = response.getBody();
            if (!"success".equalsIgnoreCase(String.valueOf(responseBody.get("status")))) {
                throw new RuntimeException("Product Manager URL allocation returned status: " + responseBody.get("status"));
            }
            return responseBody;
        } catch (ResourceAccessException e) {
            throw new IOException("Failed to reach Product Manager for URL allocation", e);
        } catch (HttpStatusCodeException e) {
            throw new IOException(
                    "Product Manager URL allocation failed with HTTP " + e.getStatusCode().value()
                            + ": " + e.getResponseBodyAsString(),
                    e
            );
        }
    }

    private Map<String, Object> callProductManagerProductProvisioning(
            String url,
            String realmName,
            String productId,
            String backendRepoName,
            String frontendRepoName,
            Path backendZipFile,
            Path frontendZipFile
    ) throws IOException {
        long backendZipSizeBytes = Files.size(backendZipFile);
        long frontendZipSizeBytes = Files.size(frontendZipFile);
        log.info(
                "Uploading product ZIPs to Product Manager (backend: {} bytes, frontend: {} bytes)",
                backendZipSizeBytes,
                frontendZipSizeBytes
        );

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            LinkedMultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            body.add("realmName", realmName);
            body.add("productId", productId);
            body.add("backendRepoName", backendRepoName);
            body.add("frontendRepoName", frontendRepoName);
            body.add("backendZip", new org.springframework.core.io.FileSystemResource(backendZipFile.toFile()));
            body.add("frontendZip", new org.springframework.core.io.FileSystemResource(frontendZipFile.toFile()));

            HttpEntity<LinkedMultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("Product Manager returned HTTP " + response.getStatusCode().value());
            }
            if (response.getBody() == null) {
                throw new RuntimeException("Product Manager returned empty response");
            }

            Map<String, Object> responseBody = response.getBody();
            if (!"success".equalsIgnoreCase(String.valueOf(responseBody.get("status")))) {
                throw new RuntimeException("Product Manager returned status: " + responseBody.get("status"));
            }
            return responseBody;
        } catch (ResourceAccessException e) {
            throw new IOException("Failed to upload product ZIPs to Product Manager", e);
        } catch (HttpStatusCodeException e) {
            throw new IOException(
                    "Product Manager returned HTTP " + e.getStatusCode().value() +
                            " while provisioning product. Response body: " + e.getResponseBodyAsString(),
                    e
            );
        } catch (Exception e) {
            throw new IOException("Failed to call Product Manager product provisioning: " + e.getMessage(), e);
        }
    }

    private String requireString(Map<String, Object> values, String key) {
        Object value = values.get(key);
        if (value == null || value.toString().isBlank()) {
            throw new IllegalStateException("Product Manager response is missing required field: " + key);
        }
        return value.toString();
    }

    private void cleanupTempFile(Path path) {
        if (path == null) {
            return;
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException ex) {
            log.warn("Failed to cleanup temporary file '{}': {}", path, ex.getMessage());
        }
    }

    private void provisionRepositoryViaProductManager(String repoName, Path codePath) throws IOException {
        String provisionUrl = projectManagementBaseUrl + provisionUploadPath;
        
        log.info("Provisioning repository '{}' via Product Manager at {}", repoName, provisionUrl);
        
        Path zipFile = null;
        try {
            // Create ZIP from code directory
            zipFile = createZipFromDirectory(codePath);
            log.debug("Created ZIP file for upload: {}", zipFile);
            
            // Call Product Manager REST endpoint
            callProductManagerProvisioning(provisionUrl, repoName, zipFile);
            
            log.info("✅ Repository '{}' provisioned successfully via Product Manager", repoName);
            
        } catch (Exception e) {
            log.error("❌ Failed to provision repository via Product Manager: {}", e.getMessage());
            throw new RuntimeException("Product Manager provisioning failed for repo: " + repoName, e);
        } finally {
            // Cleanup ZIP file
            if (zipFile != null && Files.exists(zipFile)) {
                try {
                    Files.deleteIfExists(zipFile);
                    log.debug("Cleaned up temporary ZIP file: {}", zipFile);
                } catch (Exception e) {
                    log.warn("Failed to cleanup ZIP file: {}", e.getMessage());
                }
            }
        }
    }

    /**
     * Call Product Manager provisioning endpoint with multipart form data
     */
    private void callProductManagerProvisioning(String url, String repoName, Path zipFile) throws IOException {
        log.debug("Calling Product Manager endpoint: POST {}", url);
        long zipSizeBytes = Files.size(zipFile);
        double zipSizeMb = zipSizeBytes / (1024.0 * 1024.0);
        log.info("Uploading ZIP for repo '{}' to Product Manager (size: {} bytes / {} MB)",
                repoName, zipSizeBytes, String.format("%.2f", zipSizeMb));
        
        try {
            // Build multipart form data
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            
            LinkedMultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            body.add("repoName", repoName);
            body.add("zipFile", new org.springframework.core.io.FileSystemResource(zipFile.toFile()));
            
            HttpEntity<LinkedMultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);
            
            // Send request to Product Manager
            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
            
            log.debug("Product Manager response status: {}", response.getStatusCode());
            
            // Check if successful
            if (!response.getStatusCode().is2xxSuccessful()) {
                String errorMsg = "Product Manager returned HTTP " + response.getStatusCode().value();
                log.error("❌ {}", errorMsg);
                throw new RuntimeException(errorMsg);
            }
            
            // Verify response body
            if (response.getBody() != null) {
                String status = (String) response.getBody().get("status");
                if ("success".equalsIgnoreCase(status)) {
                    log.info("✅ Product Manager confirmed successful provisioning for: {}", repoName);
                    return;
                } else {
                    String errorMsg = "Product Manager returned status: " + status;
                    log.error("❌ {}", errorMsg);
                    throw new RuntimeException(errorMsg);
                }
            } else {
                throw new RuntimeException("Product Manager returned empty response");
            }
        } catch (ResourceAccessException e) {
            String enhancedMessage = "Failed to upload ZIP to Product Manager for repo '" + repoName +
                    "' (ZIP size: " + String.format("%.2f", zipSizeMb) + " MB). " +
                    "This usually indicates Product Manager rejected the multipart request (size/connector limits) " +
                    "or closed the connection during upload.";
            log.error("REST call to Product Manager failed: {}", enhancedMessage, e);
            throw new IOException(enhancedMessage, e);
        } catch (HttpStatusCodeException e) {
            String responseBody = e.getResponseBodyAsString();
            String enhancedMessage = "Product Manager returned HTTP " + e.getStatusCode().value() +
                    " for repo '" + repoName + "'. Response body: " + responseBody;
            log.error("REST call to Product Manager failed: {}", enhancedMessage, e);
            throw new IOException(enhancedMessage, e);
        } catch (Exception e) {
            log.error("REST call to Product Manager failed: {}", e.getMessage(), e);
            throw new IOException("Failed to call Product Manager: " + e.getMessage(), e);
        }
    }

    /**
     * Create a ZIP file from a directory for upload to Product Manager
     */
    private Path createZipFromDirectory(Path sourceDir) throws IOException {
        Path zipFile = Files.createTempFile("provisioning-", ".zip");
        
        try (java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(
                Files.newOutputStream(zipFile))) {
            
            Files.walk(sourceDir)
                .filter(Files::isRegularFile)
                .forEach(file -> {
                    try {
                        String zipEntryName = sourceDir.relativize(file).toString().replace("\\", "/");
                        java.util.zip.ZipEntry entry = new java.util.zip.ZipEntry(zipEntryName);
                        zos.putNextEntry(entry);
                        Files.copy(file, zos);
                        zos.closeEntry();
                        log.debug("Added to ZIP: {}", zipEntryName);
                    } catch (IOException e) {
                        throw new RuntimeException("Failed to add file to ZIP: " + file, e);
                    }
                });
        } catch (RuntimeException e) {
            Files.deleteIfExists(zipFile);
            throw new IOException("Failed to create ZIP file: " + e.getMessage(), e.getCause());
        }
        
        long zipSize = Files.size(zipFile);
        log.debug("Created ZIP file: {} (size: {} bytes)", zipFile, zipSize);
        return zipFile;
    }
}

