package com.paxaris.identity_service.controller;

import com.paxaris.identity_service.service.DynamicJwtDecoder;
import com.paxaris.identity_service.service.KeycloakClientService;
import com.paxaris.identity_service.service.KeycloakService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final RestTemplate restTemplate;
    private final DynamicJwtDecoder jwtDecoder;
    private final KeycloakClientService keycloakClientService;
    private final KeycloakService keycloakService;

    // ===================== LOGIN =====================
    @PostMapping("/login/{realm}")
    public ResponseEntity<?> login(
            @PathVariable String realm,
            @RequestParam String clientId,
            @RequestParam(required = false) String clientSecret,
            @RequestParam String username,
            @RequestParam String password) {

        log.info("Received login request from API Gateway");
        log.info("Realm: {}", realm);
        log.info("ClientId: {}", clientId);
        log.info("Username: {}", username);
        log.info("ClientSecret provided: {}", clientSecret != null);

        String url = "http://localhost:8080/realms/" + realm + "/protocol/openid-connect/token";

        var body = new LinkedMultiValueMap<String, String>();
        body.add("grant_type", "password");
        body.add("client_id", clientId);
        if (clientSecret != null) body.add("client_secret", clientSecret);
        body.add("username", username);
        body.add("password", password);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(url, body, Map.class);
            Map<String, Object> tokenResponse = response.getBody();
            String accessToken = (String) tokenResponse.get("access_token");

            // Decode and validate token
            Jwt jwt = jwtDecoder.decode(accessToken);

            // Extract roles from token using KeycloakService
            List<String> roles = keycloakService.getRoleFromToken(accessToken);

            // Prepare payload to return
            Map<String, Object> payload = new HashMap<>(jwt.getClaims());
            payload.put("access_token", accessToken);
            payload.put("refresh_token", tokenResponse.get("refresh_token"));
            payload.put("expires_in", tokenResponse.get("expires_in"));
            payload.put("scope", tokenResponse.get("scope"));
            payload.put("roles", roles); // Add roles directly

            log.info("Login successful for user: {}", username);
            return ResponseEntity.ok(payload);

        } catch (JwtException e) {
            log.error("JWT validation failed for user {}: {}", username, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid token", "message", e.getMessage()));
        } catch (Exception e) {
            log.error("Login failed for user {}: {}", username, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Login failed", "message", e.getMessage()));
        }
    }

    // ===================== VALIDATE TOKEN =====================
    @GetMapping("/validate/{realm}")
    public ResponseEntity<?> validateToken(
            @PathVariable String realm,
            @RequestHeader("Authorization") String authHeader) {

        log.info("Received token validation request for realm: {}", realm);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Missing or invalid Authorization header"));
        }

        String token = authHeader.substring("Bearer ".length());

        try {
            Jwt jwt = jwtDecoder.decode(token);

            // Extract roles
            List<String> roles = keycloakService.getRoleFromToken(token);

            Map<String, Object> payload = new HashMap<>(jwt.getClaims());
            payload.put("valid", true);
            payload.put("roles", roles);

            log.info("Token validation successful");
            return ResponseEntity.ok(payload);

        } catch (JwtException e) {
            log.error("Token validation failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid token", "message", e.getMessage()));
        }
    }
}
