# Login Flow Documentation - Identity Service
## Overview
This document explains the complete login flow in the Identity Service, detailing what steps are performed during login and what response is sent back to the API Gateway after successful authentication.
---
## Login Endpoints
There are **TWO** main login endpoints available:
### 1. **AuthController Login** - /auth/login/{realm}
**Path:** `POST /auth/login/{realm}`
### 2. **KeycloakClientController Login** - `/{realm}/login`
**Path:** `POST /{realm}/login`
---
## Login Flow Steps (Detailed)
### **Endpoint 1: /auth/login/{realm}**
#### **Step 1: Receive Login Request**
The API Gateway sends a login request with the following parameters:
- **realm** (path variable): The Keycloak realm name
- **clientId** (request param): The client application ID
- **clientSecret** (optional request param): Client secret if required
- **username** (request param): User's username
- **password** (request param): User's password
**Logging:**
`java
log.info("Received login request from API Gateway");
log.info("Realm: {}", realm);
log.info("ClientId: {}", clientId);
log.info("Username: {}", username);
`
---
#### **Step 2: Prepare Keycloak Token Request**
Constructs a request to Keycloak's token endpoint:
- **URL:** `http://localhost:8080/realms/{realm}/protocol/openid-connect/token`
- **Grant Type:** `password` (Resource Owner Password Credentials flow)
- **Body Parameters:**
  - `grant_type`: "password"
  - `client_id`: The client ID
  - `client_secret`: Client secret (if provided)
  - `username`: User's username
  - `password`: User's password
---
#### **Step 3: Request Token from Keycloak**
Sends HTTP POST request to Keycloak using `RestTemplate`:
`java
ResponseEntity<Map> response = restTemplate.postForEntity(url, body, Map.class);
Map<String, Object> tokenResponse = response.getBody();
String accessToken = (String) tokenResponse.get("access_token");
`
**Keycloak Returns:**
- `access_token`: JWT access token
- `refresh_token`: Refresh token for obtaining new access tokens
- `expires_in`: Token expiration time (in seconds)
- `scope`: Granted scopes
- Other OAuth2 token response fields
---
#### **Step 4: Decode and Validate JWT Token**
Uses `DynamicJwtDecoder` to decode and validate the JWT:
`java
Jwt jwt = jwtDecoder.decode(accessToken);
`
**Validation includes:**
- Signature verification
- Expiration check
- Issuer validation
- Audience validation
---
#### **Step 5: Extract Roles from Token**
Calls `KeycloakService.getRoleFromToken()` to extract user roles:
**Role Extraction Logic:**
1. **First, checks for Realm Roles:**
   `java
   Map<String, Object> realmAccess = payload.get("realm_access");
   if (realmAccess != null && realmAccess.containsKey("roles")) {
       return (List<String>) realmAccess.get("roles");
   }
   `
2. **If no realm roles, checks for Client Roles:**
   `java
   Map<String, Object> resourceAccess = payload.get("resource_access");
   if (resourceAccess != null) {
       List<String> roles = new ArrayList<>();
       for (Object value : resourceAccess.values()) {
           Map<String, Object> entry = (Map<String, Object>) value;
           if (entry.containsKey("roles")) {
               roles.addAll((List<String>) entry.get("roles"));
           }
       }
       return roles;
   }
   `
---
#### **Step 6: Prepare Response Payload**
Constructs the final response with:
`java
Map<String, Object> payload = new HashMap<>(jwt.getClaims());
payload.put("access_token", accessToken);
payload.put("refresh_token", tokenResponse.get("refresh_token"));
payload.put("expires_in", tokenResponse.get("expires_in"));
payload.put("scope", tokenResponse.get("scope"));
payload.put("roles", roles);
`
---
#### **Step 7: Return Success Response**
Sends HTTP 200 OK response to API Gateway with complete payload:
`java
log.info("Login successful for user: {}", username);
return ResponseEntity.ok(payload);
`
---
## Response Structure Sent to API Gateway
### **Success Response (HTTP 200 OK)**
#### From /auth/login/{realm}:
`json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "scope": "openid profile email",
  "roles": ["admin", "user", "manager"],
  // All JWT claims are also included:
  "sub": "user-id-12345",
  "iss": "http://localhost:8080/realms/my-realm",
  "aud": ["account", "product-service"],
  "exp": 1709625600,
  "iat": 1709625300,
  "preferred_username": "john.doe",
  "email": "john.doe@example.com",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "azp": "product-service",
  "realm_access": {
    "roles": ["offline_access", "uma_authorization"]
  },
  "resource_access": {
    "product-service": {
      "roles": ["admin", "user"]
    }
  }
}
`
#### From /{realm}/login:
`json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "token_type": "Bearer",
  "azp": "product-service",
  "roles": ["admin", "user", "manager"],
  "realm": "my-realm",
  "product": "product-service",
  "redirect_url": "http://localhost:3000/dashboard"
}
`
---
### **Error Responses**
#### 1. **JWT Validation Failed (HTTP 401 UNAUTHORIZED)**
`json
{
  "error": "Invalid token",
  "message": "JWT signature validation failed"
}
`
#### 2. **Login Failed (HTTP 401 UNAUTHORIZED)**
`json
{
  "error": "Login failed",
  "message": "Invalid username or password"
}
`
#### 3. **Internal Server Error (HTTP 500)**
`json
{
  "error": "Login failed",
  "message": "Connection timeout to Keycloak"
}
`
---
## Login Flow Diagram
\\\
API Gateway
    |
    | POST /auth/login/{realm}
    | (username, password, clientId, clientSecret)
    |
    v
Identity Service (AuthController)
    |
    | Step 1: Log request details
    |
    | Step 2: Prepare token request body
    |
    v
Keycloak Server
    | POST /realms/{realm}/protocol/openid-connect/token
    |
    | Authenticates user
    | Generates tokens
    |
    v
Identity Service
    |
    | Step 3: Receive tokens from Keycloak
    |
    | Step 4: Decode JWT using DynamicJwtDecoder
    |        - Validate signature
    |        - Check expiration
    |
    | Step 5: Extract roles (KeycloakService)
    |        - Check realm_access.roles
    |        - Check resource_access.*.roles
    |
    | Step 6: Build response payload
    |        - All JWT claims
    |        - access_token
    |        - refresh_token
    |        - expires_in
    |        - scope
    |        - roles (extracted)
    |
    | Step 7: Return ResponseEntity.ok(payload)
    |
    v
API Gateway
    |
    | Receives complete authentication response
    | Can now use access_token for subsequent requests
    |
    v
Client Application
\\\
---
## Key Components Involved
### 1. **AuthController**
- **Location:** `com.paxaris.identity_service.controller.AuthController`
- **Responsibility:** Handles login requests, orchestrates the authentication flow
- **Key Methods:**
  - `login()`: Main login endpoint
  - `validateToken()`: Token validation endpoint
### 2. **DynamicJwtDecoder**
- **Location:** `com.paxaris.identity_service.service.DynamicJwtDecoder`
- **Responsibility:** Decodes and validates JWT tokens
- **Features:**
  - Dynamic JWKS key resolution
  - Multi-realm support
  - Signature verification
### 3. **KeycloakService**
- **Location:** `com.paxaris.identity_service.service.KeycloakService`
- **Responsibility:** Extracts roles and validates tokens
- **Key Methods:**
  - `getRoleFromToken()`: Extracts roles from JWT
  - `validateAndGetUsername()`: Validates token and gets username
### 4. **RestTemplate**
- **Responsibility:** HTTP client for communicating with Keycloak
- **Configuration:** Defined in Spring configuration
---
## Security Considerations
### 1. **Token Validation**
- JWT signature is verified using Keycloak's public key
- Token expiration is checked
- Issuer (iss) claim is validated
### 2. **Client Secret Handling**
- Client secret is optional
- Only sent to Keycloak if provided
- Not logged in plain text
### 3. **Error Handling**
- Generic error messages returned to prevent information leakage
- Detailed errors logged server-side for debugging
### 4. **HTTPS**
- In production, all communication should use HTTPS
- Currently configured for localhost development
---
## Additional Login Features
### Token Validation Endpoint
**Path:** `GET /auth/validate/{realm}`
**Purpose:** Validate an existing token without re-authenticating
**Request:**
`
GET /auth/validate/my-realm
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
`
**Response:**
`json
{
  "valid": true,
  "roles": ["admin", "user"],
  "sub": "user-id-12345",
  "preferred_username": "john.doe",
  // ... all JWT claims
}
`
---
## Alternative Login Endpoint (/{realm}/login)
This endpoint provides **additional information** in the response:
### Extra Fields Returned:
1. **azp** (Authorized Party): The client ID that requested the token
2. **realm**: Extracted realm name from the issuer claim
3. **product**: Same as azp, the client/product identifier
4. **redirect_url**: The configured redirect URL for the client
### Role Extraction:
- Merges both **realm roles** and **client roles**
- Returns all roles in a single `roles` array
---
## Usage Example
### Request to API Gateway:
`ash
curl -X POST "http://api-gateway:8080/identity/auth/login/my-realm" \
  -d "username=john.doe" \
  -d "password=secretpassword" \
  -d "clientId=product-service" \
  -d "clientSecret=client-secret-123"
`
### Response from Identity Service to API Gateway:
`json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMzQ1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teS1yZWFsbSIsImF6cCI6InByb2R1Y3Qtc2VydmljZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImpvaG4uZG9lIiwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJhZG1pbiIsInVzZXIiXX19...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "scope": "openid profile email",
  "roles": ["admin", "user"],
  "sub": "user-12345",
  "iss": "http://localhost:8080/realms/my-realm",
  "azp": "product-service",
  "preferred_username": "john.doe",
  "email": "john.doe@example.com"
}
`
### API Gateway can then:
1. Return the `access_token` to the client
2. Store the token for subsequent requests
3. Use the `roles` for authorization decisions
4. Forward the token to downstream services
---
## Common Issues and Troubleshooting
### 1. **401 Unauthorized**
- **Cause:** Invalid credentials or client configuration
- **Check:** Username, password, clientId in Keycloak
### 2. **JWT Validation Failed**
- **Cause:** Token signature mismatch or expired token
- **Check:** Keycloak public key configuration, token expiration time
### 3. **No Roles Returned**
- **Cause:** User has no roles assigned in Keycloak
- **Check:** User's role mappings in Keycloak admin console
### 4. **Connection Timeout**
- **Cause:** Keycloak server unreachable
- **Check:** Keycloak URL configuration, network connectivity
---
## Configuration Properties
### Required Properties (application.properties):
`properties
# Keycloak Base URL
keycloak.base-url=http://localhost:8080
# Master Realm Credentials
keycloak.master-realm.admin-username=admin
keycloak.master-realm.admin-password=admin
keycloak.master-realm.client-id=admin-cli
# JWT Decoder Configuration
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8080/realms/master
`
---
## Summary
**What happens during login:**
1. ? API Gateway sends credentials to Identity Service
2. ? Identity Service forwards to Keycloak for authentication
3. ? Keycloak authenticates user and returns JWT tokens
4. ? Identity Service decodes and validates JWT
5. ? Identity Service extracts user roles from token
6. ? Identity Service builds comprehensive response payload
7. ? API Gateway receives access_token + user info + roles
**Response to API Gateway includes:**
- ? `access_token` - for authenticating subsequent requests
- ? `refresh_token` - for obtaining new access tokens
- ? `expires_in` - token lifetime
- ? `scope` - granted OAuth2 scopes
- ? `roles` - user's roles (both realm and client roles)
- ? All JWT claims (sub, iss, azp, email, name, etc.)
**This comprehensive response allows the API Gateway to:**
- Authenticate future requests using the access_token
- Make authorization decisions based on roles
- Display user information to the client
- Refresh tokens when they expire
---
## End of Documentation
