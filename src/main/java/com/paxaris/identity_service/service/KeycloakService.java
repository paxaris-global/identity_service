package com.paxaris.identity_service.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;



    // ===================== ROLES EXTRACTION =====================
    public List<String> getRoleFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) return List.of();

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
            Map<String, Object> payload = objectMapper.readValue(payloadJson, Map.class);

            // Realm roles
            Map<String, Object> realmAccess = (Map<String, Object>) payload.get("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                return (List<String>) realmAccess.get("roles");
            }

            // Client roles
            Map<String, Object> resourceAccess = (Map<String, Object>) payload.get("resource_access");
            if (resourceAccess != null) {
                List<String> roles = new ArrayList<>();
                for (Object value : resourceAccess.values()) {
                    Map<String, Object> entry = (Map<String, Object>) value;
                    if (entry.containsKey("roles")) {
                        roles.addAll((List<String>) entry.get("roles"));
                    }
                }
                return roles;
            }

            return List.of();
        } catch (Exception e) {
            log.error("Error extracting roles from token: {}", e.getMessage(), e);
            return List.of();
        }
    }
}
