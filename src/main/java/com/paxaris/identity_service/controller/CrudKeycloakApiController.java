package com.paxaris.identity_service.controller;

import com.paxaris.identity_service.dto.RoleCreationRequest;
import com.paxaris.identity_service.dto.RoleRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/crud")
@RequiredArgsConstructor
@Slf4j
public class CrudKeycloakApiController {

    private final RestTemplate restTemplate = new RestTemplate();

    // ---------------- CREATE ROLE ----------------
    @PostMapping("/roles/{realm}/{client}")
    public ResponseEntity<String> createRole(
            @PathVariable String realm,
            @PathVariable String client,
            @RequestBody RoleRequest request,
            @RequestHeader("Authorization") String authHeader) {

        try {
            // 1️⃣ Call Keycloak first
            String keycloakUrl = "http://localhost:8080/keycloak/roles/" + realm + "/" + client;
            log.info("Calling Keycloak CREATE ROLE at: {}", keycloakUrl);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("Authorization", authHeader);

            RoleCreationRequest kcRequest = new RoleCreationRequest();
            kcRequest.setName(request.getRoleName());
            kcRequest.setDescription(request.getDescription());

            ResponseEntity<String> keycloakResponse = restTemplate.postForEntity(
                    keycloakUrl,
                    new HttpEntity<>(kcRequest, headers),
                    String.class
            );

            log.info("Keycloak response: {}", keycloakResponse.getStatusCode());

            // 2️⃣ Only if Keycloak succeeded, call Project Manager
            if (keycloakResponse.getStatusCode().is2xxSuccessful()) {
                String projectManagerUrl = "http://localhost:8088/project/roles/save-or-update";
                log.info("Calling Project Manager CREATE/UPDATE ROLE at: {}", projectManagerUrl);

                ResponseEntity<String> pmResponse = restTemplate.postForEntity(
                        projectManagerUrl,
                        new HttpEntity<>(request, headers),
                        String.class
                );
                log.info("Project Manager response: {}", pmResponse.getStatusCode());
            } else {
                log.warn("Keycloak CREATE ROLE failed, skipping Project Manager call.");
            }

            return ResponseEntity.status(keycloakResponse.getStatusCode())
                    .body(keycloakResponse.getBody());

        } catch (Exception e) {
            log.error("Error creating role via Keycloak/ProjectManager", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage());
        }
    }

    // ---------------- UPDATE ROLE ----------------
    @PutMapping("/roles/{realm}/{client}/{roleName}")
    public ResponseEntity<String> updateRole(
            @PathVariable String realm,
            @PathVariable String client,
            @PathVariable String roleName,
            @RequestBody RoleRequest request,
            @RequestHeader("Authorization") String authHeader) {

        try {
            String keycloakUrl = "http://localhost:8080/keycloak/roles/" + realm + "/" + client + "/" + roleName;
            log.info("Calling Keycloak UPDATE ROLE at: {}", keycloakUrl);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("Authorization", authHeader);

            RoleCreationRequest kcRequest = new RoleCreationRequest();
            kcRequest.setName(request.getRoleName());
            kcRequest.setDescription(request.getDescription());

            ResponseEntity<String> keycloakResponse = restTemplate.exchange(
                    keycloakUrl,
                    HttpMethod.PUT,
                    new HttpEntity<>(kcRequest, headers),
                    String.class
            );

            log.info("Keycloak response: {}", keycloakResponse.getStatusCode());

            if (keycloakResponse.getStatusCode().is2xxSuccessful()) {
                String projectManagerUrl = "http://localhost:8088/project/roles/save-or-update";
                log.info("Calling Project Manager CREATE/UPDATE ROLE at: {}", projectManagerUrl);

                ResponseEntity<String> pmResponse = restTemplate.postForEntity(
                        projectManagerUrl,
                        new HttpEntity<>(request, headers),
                        String.class
                );
                log.info("Project Manager response: {}", pmResponse.getStatusCode());
            } else {
                log.warn("Keycloak UPDATE ROLE failed, skipping Project Manager call.");
            }

            return ResponseEntity.status(keycloakResponse.getStatusCode())
                    .body(keycloakResponse.getBody());

        } catch (Exception e) {
            log.error("Error updating role via Keycloak/ProjectManager", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage());
        }
    }

    // ---------------- DELETE ROLE ----------------
    @DeleteMapping("/roles/{realm}/{client}/{id}")
    public ResponseEntity<String> deleteRole(
            @PathVariable String realm,
            @PathVariable String client,
            @PathVariable Long id,
            @RequestHeader("Authorization") String authHeader) {

        try {
            String keycloakUrl = "http://localhost:8080/keycloak/roles/" + realm + "/" + client + "/" + id;
            log.info("Calling Keycloak DELETE ROLE at: {}", keycloakUrl);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", authHeader);

            ResponseEntity<String> keycloakResponse = restTemplate.exchange(
                    keycloakUrl,
                    HttpMethod.DELETE,
                    new HttpEntity<>(headers),
                    String.class
            );

            log.info("Keycloak response: {}", keycloakResponse.getStatusCode());

            if (keycloakResponse.getStatusCode().is2xxSuccessful()) {
                String projectManagerUrl = "http://localhost:8088/project/roles/" + id;
                log.info("Calling Project Manager DELETE ROLE at: {}", projectManagerUrl);

                ResponseEntity<String> pmResponse = restTemplate.exchange(
                        projectManagerUrl,
                        HttpMethod.DELETE,
                        new HttpEntity<>(headers),
                        String.class
                );
                log.info("Project Manager response: {}", pmResponse.getStatusCode());
            } else {
                log.warn("Keycloak DELETE ROLE failed, skipping Project Manager call.");
            }

            return ResponseEntity.status(keycloakResponse.getStatusCode())
                    .body(keycloakResponse.getBody());

        } catch (Exception e) {
            log.error("Error deleting role via Keycloak/ProjectManager", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage());
        }
    }
}
