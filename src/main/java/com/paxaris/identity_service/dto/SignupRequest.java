// src/main/java/com/paxaris/identity_service/dto/SignupRequest.java

package com.paxaris.identity_service.dto;

import lombok.Data;

@Data
public class SignupRequest {

    private String realmName;
    private String clientId;
    private boolean publicClient = true;
    private AdminUser adminUser;

    @Data
    public static class AdminUser {
        private String username;
        private String email;
        private String password;
        private String firstName;
        private String lastName;
    }
    private String url;
    private String uri;
}