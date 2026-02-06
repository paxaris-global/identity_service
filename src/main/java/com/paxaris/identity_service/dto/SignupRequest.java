package com.paxaris.identity_service.dto;

import lombok.Data;

@Data
public class SignupRequest {

    // user input
    private String realmName;

    // user input (password for admin)
    private String adminPassword;

    // optional — default to "admin" if null
    private String adminUsername = "admin";
}
