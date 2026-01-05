// src/main/java/com/paxaris/identity_service/dto/KeycloakConfig.java

package com.paxaris.identity_service.dto; // Changed package to model as it's a configuration model

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakConfig {
    private String baseUrl;
    private String adminUsername;
    private String adminPassword;
    private String clientId;
    private String realm;
}
