package com.paxaris.identity_service.service;

import com.nimbusds.jwt.JWTParser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

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

    @Value("${identity.jwt.issuer-host-rewrite.from}")
    private String issuerHostRewriteFrom;

    @Value("${identity.jwt.issuer-host-rewrite.to}")
    private String issuerHostRewriteTo;

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            String issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();

            if (issuer == null || issuer.isBlank()) {
                throw new JwtException("Issuer (iss) claim missing in token");
            }

            // Rewrite issuer host when needed (for local vs container hostname differences)
            if (StringUtils.hasText(issuerHostRewriteFrom)
                    && StringUtils.hasText(issuerHostRewriteTo)
                    && issuer.contains(issuerHostRewriteFrom)) {
                issuer = issuer.replace(issuerHostRewriteFrom, issuerHostRewriteTo);
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
