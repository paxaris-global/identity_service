package com.paxaris.identity_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UrlEntry {
    private Long id;   // optional for update
    private String url;
    private String uri;
}