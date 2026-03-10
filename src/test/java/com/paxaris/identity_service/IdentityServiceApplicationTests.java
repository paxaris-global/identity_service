package com.paxaris.identity_service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
        "PROJECT_MANAGER_URL=http://localhost:8088",
        "KEYCLOAK_BASE_URL=http://localhost:8080",
        "KEYCLOAK_REALM=test-realm",
        "KEYCLOAK_ADMIN=test-admin",
        "KEYCLOAK_ADMIN_PASSWORD=test-password",
        "DOCKER_USERNAME=test-user",
        "DOCKER_PASSWORD=test-password",
        "GITHUB_ORG=test-org",
        "GITHUB_TOKEN=test-token"
})
class IdentityServiceApplicationTests {

    @Test
    void contextLoads() {
    }
}
