package com.paxaris.identity_service.config;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@SecurityScheme(
        name = "bearer",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        description = "JWT authentication token",
        in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {

        @Value("${springdoc.info.title:Identity Service API}")
        private String apiTitle;

        @Value("${springdoc.info.version:1.0.0}")
        private String apiVersion;

        @Value("${springdoc.info.description:Identity Service provides authentication and authorization APIs using Keycloak}")
        private String apiDescription;

        @Value("${springdoc.info.contact.name:Paxaris Global}")
        private String contactName;

        @Value("${springdoc.info.contact.url:https://paxarisglobal.com}")
        private String contactUrl;

        @Value("${springdoc.info.contact.email:support@paxarisglobal.com}")
        private String contactEmail;

        @Value("${springdoc.info.license.name:Apache 2.0}")
        private String licenseName;

        @Value("${springdoc.info.license.url:https://www.apache.org/licenses/LICENSE-2.0.html}")
        private String licenseUrl;

        @Value("${springdoc.external-docs.description:Keycloak Documentation}")
        private String externalDocsDescription;

        @Value("${springdoc.external-docs.url:https://www.keycloak.org/docs/latest/}")
        private String externalDocsUrl;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title(apiTitle)
                        .version(apiVersion)
                        .description(apiDescription)
                        .contact(new Contact()
                                .name(contactName)
                                .url(contactUrl)
                                .email(contactEmail))
                        .license(new License()
                                .name(licenseName)
                                .url(licenseUrl)))
                .externalDocs(new ExternalDocumentation()
                        .description(externalDocsDescription)
                        .url(externalDocsUrl))
                .addSecurityItem(new SecurityRequirement().addList("bearer"))
                .components(new Components()
                        .addSecuritySchemes("bearer",
                                new io.swagger.v3.oas.models.security.SecurityScheme()
                                        .type(io.swagger.v3.oas.models.security.SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("JWT Token Authentication")));
    }
}

