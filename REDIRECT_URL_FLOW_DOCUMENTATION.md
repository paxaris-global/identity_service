# 🔗 Redirect URL Flow - Identity Service
## Overview
When a user logs in via the **POST /{realm}/login** endpoint, the Identity Service fetches the redirect URL from Keycloak and returns it to the API Gateway along with the authentication response.
---
## 🔄 Complete Flow with Redirect URL
### **Step 1: User Login Request**
`
Client → API Gateway → Identity Service
POST /{realm}/login
Body: { username, password, client_id }
`
### **Step 2: Authenticate with Keycloak**
`java
// Get access token from Keycloak
Map<String, Object> tokenMap = clientService.getMyRealmToken(username, password, clientId, realm);
String accessToken = tokenMap.get("access_token");
`
### **Step 3: Fetch Redirect URL from Keycloak**
`java
// Line 134 in KeycloakClientController.java
String redirectUrl = clientService.getClientRedirectUrl(realm, clientId);
`
### **Step 4: Build Response with Redirect URL**
`java
// Lines 154-160 in KeycloakClientController.java
Map<String, Object> response = new HashMap<>();
response.put("access_token", keycloakToken);
response.put("expires_in", tokenMap.get("expires_in"));
response.put("token_type", tokenMap.get("token_type"));
response.put("azp", azp);
response.put("roles", allRoles);
response.put("realm", extractedRealm);
response.put("product", product);
response.put("redirect_url", redirectUrl);  // ✅ Redirect URL included
`
### **Step 5: Return to API Gateway**
`
Identity Service → API Gateway
HTTP 200 OK
Body: { access_token, roles, realm, product, redirect_url }
`
---
## 🔍 How getClientRedirectUrl() Works
**Location:** KeycloakClientServiceImpl.java (lines 178-227)
### **Method Signature:**
`java
public String getClientRedirectUrl(String realm, String clientId)
`
### **Process:**
#### **1. Get Admin Token**
`java
String adminToken = getMasterToken();
`
- Uses Keycloak master admin credentials
- Required to access Keycloak Admin REST API
#### **2. Search for Client by clientId**
`java
String clientSearchUrl = config.getBaseUrl()
    + "/admin/realms/" + realm
    + "/clients?clientId=" + clientId;
ResponseEntity<List> searchResponse = restTemplate.exchange(
    clientSearchUrl, HttpMethod.GET, request, List.class
);
`
- **API Call:** GET /admin/realms/{realm}/clients?clientId={clientId}
- **Returns:** List of clients matching the clientId
- **Extract:** Client UUID from the first result
#### **3. Get Full Client Details**
`java
String clientDetailsUrl = config.getBaseUrl()
    + "/admin/realms/" + realm
    + "/clients/" + clientUuid;
ResponseEntity<Map> clientResponse = restTemplate.exchange(
    clientDetailsUrl, HttpMethod.GET, request, Map.class
);
`
- **API Call:** GET /admin/realms/{realm}/clients/{clientUuid}
- **Returns:** Complete client configuration including:
  - edirectUris - Array of valid redirect URIs
  - webOrigins - CORS origins
  - ootUrl - Root URL
  - aseUrl - Base URL
  - And many other client settings
#### **4. Extract First Redirect URI**
`java
Map<String, Object> clientDetails = clientResponse.getBody();
List<String> redirectUris = (List<String>) clientDetails.get("redirectUris");
return (redirectUris != null && !redirectUris.isEmpty())
    ? redirectUris.get(0)
    : null;
`
- **Returns:** The first redirect URI from the list
- **Fallback:** Returns 
ull if no redirect URIs configured
---
## 📤 Response to API Gateway
### **Complete Login Response with Redirect URL:**
`json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "token_type": "Bearer",
  "azp": "product-service",
  "roles": ["admin", "user"],
  "realm": "my-realm",
  "product": "product-service",
  "redirect_url": "http://localhost:3000/dashboard"  // ✅ Redirect URL
}
`
---
## 🎯 How API Gateway Uses the Redirect URL
The API Gateway receives the edirect_url and can:
1. ✅ **Return it to the client** - Client app knows where to redirect after login
2. ✅ **Store it in session** - For post-login navigation
3. ✅ **Validate redirect** - Ensure it matches allowed URLs
4. ✅ **Build redirect response** - Return 302 redirect to client
### **Example API Gateway Response to Client:**
`json
{
  "status": "success",
  "access_token": "eyJhbGc...",
  "user": {
    "username": "john.doe",
    "roles": ["admin", "user"]
  },
  "redirect_url": "http://localhost:3000/dashboard"
}
`
### **Or as a Redirect:**
`http
HTTP/1.1 302 Found
Location: http://localhost:3000/dashboard?token=eyJhbGc...
Set-Cookie: access_token=eyJhbGc...; HttpOnly; Secure
`
---
## 🏗️ Where Redirect URLs are Configured
### **During Client Creation** (KeycloakClientServiceImpl.java, line 595):
`java
// For PUBLIC clients (frontend apps)
body.put("redirectUris", List.of(frontendBaseUrl + "/*"));
body.put("webOrigins", List.of(frontendBaseUrl));
body.put("rootUrl", frontendBaseUrl);
body.put("baseUrl", frontendBaseUrl);
`
**Example:**
- Frontend Base URL: http://localhost:3000
- Redirect URIs: ["http://localhost:3000/*"]
- Web Origins: ["http://localhost:3000"]
### **Redirect URIs Support Wildcards:**
- http://localhost:3000/* - Matches all paths
- http://localhost:3000/dashboard - Exact match
- http://localhost:3000/callback - Specific callback
---
## 🔄 Complete Sequence Diagram
`
┌────────┐       ┌─────────────┐       ┌──────────────────┐       ┌─────────────────┐
│ Client │       │ API Gateway │       │ Identity Service │       │ Keycloak Server │
└───┬────┘       └──────┬──────┘       └────────┬─────────┘       └────────┬────────┘
    │                   │                       │                          │
    │ 1. Login Request  │                       │                          │
    ├──────────────────►│                       │                          │
    │                   │ 2. Forward Login      │                          │
    │                   ├──────────────────────►│                          │
    │                   │                       │ 3. Authenticate User     │
    │                   │                       ├─────────────────────────►│
    │                   │                       │                          │
    │                   │                       │◄─────────────────────────┤
    │                   │                       │ 4. Access Token          │
    │                   │                       │                          │
    │                   │                       │ 5. Get Client Details    │
    │                   │                       ├─────────────────────────►│
    │                   │                       │                          │
    │                   │                       │◄─────────────────────────┤
    │                   │                       │ 6. Client Config         │
    │                   │                       │    (redirectUris)        │
    │                   │                       │                          │
    │                   │                       │ 7. Extract redirect_url  │
    │                   │                       │                          │
    │                   │◄──────────────────────┤                          │
    │                   │ 8. Login Response     │                          │
    │                   │    + redirect_url     │                          │
    │                   │                       │                          │
    │◄──────────────────┤                       │                          │
    │ 9. Complete Data  │                       │                          │
    │    + redirect_url │                       │                          │
    │                   │                       │                          │
`
---
## 📋 Key Points
### ✅ **What Happens:**
1. User logs in with credentials
2. Identity Service authenticates with Keycloak
3. Identity Service fetches client configuration from Keycloak Admin API
4. Extracts first redirect URI from client's edirectUris array
5. Returns redirect URL to API Gateway along with tokens and user info
### ✅ **Why It's Useful:**
- Frontend apps know where to navigate after login
- Supports multi-tenant apps with different redirect URLs per realm/client
- Centralized configuration in Keycloak (single source of truth)
- API Gateway doesn't need to maintain redirect URL mappings
### ✅ **Security Benefits:**
- Redirect URLs are validated by Keycloak
- Only pre-configured redirect URIs are allowed
- Prevents open redirect vulnerabilities
- Admin control over allowed redirect destinations
---
## 🛠️ Configuration Example
### **In Keycloak Admin Console:**
1. Navigate to: **Clients** → Select your client (e.g., "product-service")
2. Scroll to **Access Settings**
3. Configure:
   - **Root URL:** http://localhost:3000
   - **Valid Redirect URIs:** http://localhost:3000/*
   - **Valid Post Logout Redirect URIs:** http://localhost:3000/*
   - **Web Origins:** http://localhost:3000
### **Via Identity Service API (during signup/client creation):**
`ash
POST /signup
{
  "realm": "my-realm",
  "clientId": "my-app",
  "frontendBaseUrl": "http://localhost:3000",
  ...
}
`
The service automatically configures:
- edirectUris: ["http://localhost:3000/*"]
- webOrigins: ["http://localhost:3000"]
---
## 🐛 Troubleshooting
### **Issue: redirect_url is null**
**Cause:** Client has no redirect URIs configured in Keycloak
**Solution:**
1. Check Keycloak client configuration
2. Add redirect URI in client settings
3. Or update via API:
`ash
PUT /admin/realms/{realm}/clients/{clientUuid}
{
  "redirectUris": ["http://localhost:3000/*"]
}
`
### **Issue: Wrong redirect URL returned**
**Cause:** Multiple redirect URIs configured, wrong one selected
**Solution:**
- Method returns the **first** redirect URI in the array
- Reorder redirect URIs in Keycloak to put desired one first
- Or modify the method to select based on criteria
---
## 💡 Best Practices
1. ✅ **Use wildcards for flexibility**
   - http://localhost:3000/* covers all paths
2. ✅ **Configure multiple environments**
   - Development: http://localhost:3000/*
   - Staging: https://staging.example.com/*
   - Production: https://app.example.com/*
3. ✅ **Keep redirect URLs in sync**
   - Update Keycloak when frontend URL changes
   - Document redirect URL patterns
4. ✅ **Validate on client side**
   - Client should verify redirect_url before navigating
   - Ensure it matches expected domain
---
## 📄 Related Documentation
- **LOGIN_FLOW_DOCUMENTATION.md** - Complete login flow details
- **LOGIN_FLOW_QUICK_REFERENCE.md** - Quick reference guide
---
## Summary
✅ The **POST /{realm}/login** endpoint returns **edirect_url** to API Gateway  
✅ Redirect URL is fetched from Keycloak client configuration  
✅ Uses Keycloak Admin API with master token  
✅ Returns the **first** redirect URI from the client's configuration  
✅ API Gateway receives redirect_url in the login response  
✅ Client apps can navigate to the correct page after authentication  
**This ensures a seamless login experience with dynamic redirect handling!** 🚀
