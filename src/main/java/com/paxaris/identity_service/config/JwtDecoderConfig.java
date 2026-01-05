package com.paxaris.identity_service.config;


import com.paxaris.identity_service.service.DynamicJwtDecoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Configuration
public class JwtDecoderConfig {

    @Bean
    public JwtDecoder jwtDecoder() {
        // No hardcoded issuer; it will be discovered per request from the to
        return new DynamicJwtDecoder();
    }
}
