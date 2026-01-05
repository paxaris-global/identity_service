package com.paxaris.identity_service.service;

import com.nimbusds.jwt.JWTParser;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Dynamically resolves the JWK Set URL from the `iss` field in the JWT.
 * Supports multiple realms and avoids hardcoding Keycloak server URLs.
 */
@Component
public class DynamicJwtDecoder implements JwtDecoder {

    private final Map<String, JwtDecoder> decoderCache = new ConcurrentHashMap<>();

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            String issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();

            if (issuer == null || issuer.isBlank()) {
                throw new JwtException("Issuer (iss) claim missing in token");
            }

            // Replace localhost with docker service hostname
            if (issuer.contains("localhost")) {
                issuer = issuer.replace("localhost", "keycloak-server");
            }

            return decoderCache
                    .computeIfAbsent(issuer, this::buildDecoder)
                    .decode(token);

        } catch (ParseException e) {
            throw new JwtException("Failed to parse token", e);
        }
    }

    private JwtDecoder buildDecoder(String issuer) {
        try {
            // Keycloak always exposes JWKS at: <issuer>/protocol/openid-connect/certs
            String jwkSetUri = issuer + "/protocol/openid-connect/certs";
            return NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                    .build();
        } catch (Exception e) {
            throw new IllegalArgumentException("Could not build decoder for issuer: " + issuer, e);
        }
    }
}
