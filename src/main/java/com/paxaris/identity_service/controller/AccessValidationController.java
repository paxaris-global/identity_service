package com.paxaris.identity_service.controller;

import com.paxaris.identity_service.dto.RoleRequest;
import com.paxaris.identity_service.dto.UrlEntry;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/identity")
@RequiredArgsConstructor
public class AccessValidationController {

    private final JwtDecoder jwtDecoder;

    @PostMapping("/validate-access")
    public ResponseEntity<Boolean> validateAccess(@RequestBody ValidationRequest request) {
        try {
            String token = request.accessToken();
            String requestedUrl = request.url();

            // 1️⃣ Decode token
            Jwt decodedJwt = jwtDecoder.decode(token);

            // 2️⃣ Extract client_id and roles
            String clientId = decodedJwt.getClaim("azp"); // or "client_id" depending on Keycloak version
            Map<String, Object> resourceAccess = decodedJwt.getClaim("resource_access");

            List<String> roles = new ArrayList<>();
            if (resourceAccess != null && resourceAccess.get(clientId) != null) {
                Map<String, Object> clientRoles = (Map<String, Object>) resourceAccess.get(clientId);
                List<String> roleList = (List<String>) clientRoles.get("roles");
                if (roleList != null) roles.addAll(roleList);
            }

            String realmName = decodedJwt.getClaim("iss"); // issuer claim → realm info
            String productName = clientId;

            // 3️⃣ Call Project Manager for each role → collect allowed URLs
            RestTemplate restTemplate = new RestTemplate();
            List<String> allowedUrls = new ArrayList<>();

            for (String roleName : roles) {
                RoleRequest roleRequest = new RoleRequest();
                roleRequest.setRealmName(realmName);
                roleRequest.setProductName(productName);
                roleRequest.setRoleName(roleName);

                ResponseEntity<UrlEntry[]> pmResponse = restTemplate.postForEntity(
                        "http://localhost:8088/project/roles/get-urls",
                        roleRequest,
                        UrlEntry[].class
                );

                if (pmResponse.getBody() != null) {
                    for (UrlEntry entry : pmResponse.getBody()) {
                        String fullUrl = entry.getUrl();
                        if (!fullUrl.endsWith("/")) fullUrl += "/";
                        fullUrl += entry.getUri();
                        allowedUrls.add(fullUrl);
                    }
                }
            }

            // 4️⃣ Check if requestedUrl matches allowedUrls
            boolean isAllowed = allowedUrls.stream().anyMatch(requestedUrl::startsWith);

            return ResponseEntity.ok(isAllowed);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.ok(false);
        }
    }

    // DTO for incoming request
    private record ValidationRequest(String accessToken, String url) {}
}
