package com.paxaris.identity_service.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeycloakRealmAndClientRoleConverterTest {

    private final KeycloakRealmAndClientRoleConverter converter = new KeycloakRealmAndClientRoleConverter();

    @Test
    void convertIncludesRealmAndClientRolesWithoutDuplicates() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("realm_access", Map.of("roles", List.of("admin", "user")))
                .claim("resource_access", Map.of(
                        "portal", Map.of("roles", List.of("viewer", "admin")),
                        "reports", Map.of("roles", List.of("editor"))
                ))
                .build();

        Collection<GrantedAuthority> authorities = converter.convert(jwt);
        Set<String> values = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        assertEquals(4, values.size());
        assertTrue(values.contains("ROLE_admin"));
        assertTrue(values.contains("ROLE_user"));
        assertTrue(values.contains("ROLE_viewer"));
        assertTrue(values.contains("ROLE_editor"));
    }

    @Test
    void convertReturnsEmptyWhenClaimsMissing() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim("sub", "user")
                .build();

        Collection<GrantedAuthority> authorities = converter.convert(jwt);
        assertTrue(authorities.isEmpty());
    }
}
