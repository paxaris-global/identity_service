package com.paxaris.identity_service.externalproduct.client;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.paxaris.identity_service.dto.KeycloakConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

/**
 * Keycloak HTTP client for external product integration (client-credentials token, username lookup).
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ProductIntegrationKeycloakClient {

    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";

    private final KeycloakConfig keycloakConfig;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public String requestClientCredentialsToken(String realm, String clientId, String clientSecret) {
        String tokenUrl = buildUrl("/realms/" + realm + "/protocol/openid-connect/token");
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS);
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                tokenUrl,
                HttpMethod.POST,
                request,
                new ParameterizedTypeReference<>() {});

        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new IllegalStateException("Keycloak token request failed: " + response.getStatusCode());
        }
        Object accessToken = response.getBody().get("access_token");
        if (!(accessToken instanceof String token) || token.isBlank()) {
            throw new IllegalStateException("Keycloak did not return an access_token");
        }
        log.debug("Client credentials token obtained for product '{}' in realm '{}'", clientId, realm);
        return token;
    }

    public boolean usernameExists(String realm, String username, String bearerToken) {
        String url = buildUrl("/admin/realms/" + realm + "/users?username=" + username);
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(bearerToken);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            List<Map<String, Object>> users = objectMapper.readValue(
                    response.getBody(), new TypeReference<>() {});
            return users.stream()
                    .anyMatch(u -> username.equalsIgnoreCase((String) u.get("username")));
        } catch (HttpClientErrorException e) {
            log.error("Failed to check username '{}' in realm '{}': {}", username, realm, e.getMessage());
            throw new IllegalStateException("Failed to verify username: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Failed to check username '{}': {}", username, e.getMessage());
            throw new IllegalStateException("Failed to verify username", e);
        }
    }

    private String buildUrl(String path) {
        String base = keycloakConfig.getBaseUrl();
        if (base.endsWith("/") && path.startsWith("/")) {
            return base.substring(0, base.length() - 1) + path;
        }
        if (!base.endsWith("/") && !path.startsWith("/")) {
            return base + "/" + path;
        }
        return base + path;
    }
}
