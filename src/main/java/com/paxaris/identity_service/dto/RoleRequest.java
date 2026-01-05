package com.paxaris.identity_service.dto;

import lombok.Data;

import java.util.List;

@Data
public class RoleRequest {
    private String name;
    private String description;
    private String url;
    private String uri;

    private Long id;
    private String realmName;
    private String productName;
    private String roleName;
    private List<UrlEntry> urls;
}
