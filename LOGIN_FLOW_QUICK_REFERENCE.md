# 🔐 LOGIN FLOW - QUICK REFERENCE
## 📍 Two Login Endpoints
### 1️⃣ **POST /auth/login/{realm}** (AuthController)
   - Request params: username, password, clientId, clientSecret (optional)
   - Returns: Full JWT claims + access_token + refresh_token + roles
### 2️⃣ **POST /{realm}/login** (KeycloakClientController)  
   - Request body: JSON with username, password, client_id, client_secret
   - Returns: Tokens + roles + realm + product + redirect_url
---
## 🔄 Login Process (7 Steps)
### Step 1: Receive Request
`
API Gateway → Identity Service
Parameters: realm, username, password, clientId
`
### Step 2: Prepare Keycloak Request
`
Build token request with:
- grant_type: password
- client_id, client_secret
- username, password
`
### Step 3: Call Keycloak
`
POST http://localhost:8080/realms/{realm}/protocol/openid-connect/token
Keycloak validates credentials and returns tokens
`
### Step 4: Decode JWT
`
DynamicJwtDecoder validates:
✓ Signature (using Keycloak public key)
✓ Expiration
✓ Issuer
`
### Step 5: Extract Roles
`
KeycloakService checks:
1. realm_access.roles (realm-level roles)
2. resource_access.{client}.roles (client-level roles)
`
### Step 6: Build Response
`
Combine:
- All JWT claims (sub, iss, azp, email, name, etc.)
- access_token
- refresh_token
- expires_in
- scope
- roles (extracted array)
`
### Step 7: Return to API Gateway
`
HTTP 200 OK with complete payload
API Gateway can now authenticate requests
`
---
## 📤 Response Structure
### ✅ Success Response (HTTP 200)
`json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "expires_in": 300,
  "scope": "openid profile email",
  "roles": ["admin", "user"],
  "sub": "user-id-12345",
  "iss": "http://localhost:8080/realms/my-realm",
  "azp": "product-service",
  "preferred_username": "john.doe",
  "email": "john.doe@example.com",
  "name": "John Doe"
}
`
### ❌ Error Responses
**401 Unauthorized - Invalid Credentials:**
`json
{
  "error": "Login failed",
  "message": "Invalid username or password"
}
`
**401 Unauthorized - JWT Validation Failed:**
`json
{
  "error": "Invalid token",
  "message": "JWT signature validation failed"
}
`
---
## 🧩 Key Components
| Component | Purpose |
|-----------|---------|
| **AuthController** | Main login endpoint handler |
| **DynamicJwtDecoder** | JWT validation and decoding |
| **KeycloakService** | Role extraction from tokens |
| **RestTemplate** | HTTP client for Keycloak communication |
---
## 🔑 What API Gateway Receives
After successful login, API Gateway gets:
✅ **access_token** - Use for authenticating API requests  
✅ **refresh_token** - Get new tokens when expired  
✅ **roles** - User's permissions (e.g., ["admin", "user"])  
✅ **user info** - Username, email, name  
✅ **expires_in** - Token lifetime (seconds)  
✅ **All JWT claims** - Full token payload  
---
## 🎯 Usage Example
**Request:**
`ash
curl -X POST http://api-gateway:8080/identity/auth/login/my-realm \
  -d "username=john.doe" \
  -d "password=secret123" \
  -d "clientId=product-service"
`
**Response:**
`json
{
  "access_token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGci...",
  "expires_in": 300,
  "roles": ["admin", "user"],
  "preferred_username": "john.doe",
  "email": "john.doe@example.com"
}
`
**Next Steps:**
`ash
# Use access_token for authenticated requests
curl -H "Authorization: Bearer eyJhbGciOi..." \
  http://api-gateway:8080/api/some-protected-endpoint
`
---
## 📊 Flow Diagram
`
┌─────────────┐
│ API Gateway │
└──────┬──────┘
       │ POST /auth/login/{realm}
       │ (credentials)
       ▼
┌──────────────────┐
│ Identity Service │
└────────┬─────────┘
         │ Step 1: Receive & log request
         │ Step 2: Build token request
         ▼
┌─────────────────┐
│ Keycloak Server │ ◄── Authenticate user
└────────┬────────┘     Generate JWT tokens
         │
         │ Returns: access_token, refresh_token
         ▼
┌──────────────────┐
│ Identity Service │
└────────┬─────────┘
         │ Step 3: Receive tokens
         │ Step 4: Decode & validate JWT
         │ Step 5: Extract roles
         │ Step 6: Build response payload
         │ Step 7: Return to gateway
         ▼
┌─────────────┐
│ API Gateway │ ◄── Complete auth response
└─────────────┘     with tokens + roles + user info
`
---
## 🛡️ Security Features
✅ JWT signature verification  
✅ Token expiration validation  
✅ Issuer (iss) claim verification  
✅ Client secret optional (supports public clients)  
✅ Generic error messages (prevents info leakage)  
✅ Detailed server-side logging  
---
## 🐛 Troubleshooting
| Issue | Cause | Solution |
|-------|-------|----------|
| 401 Unauthorized | Wrong credentials | Verify username/password |
| JWT Validation Failed | Wrong public key or expired | Check Keycloak config |
| No roles returned | User has no roles | Assign roles in Keycloak |
| Connection timeout | Keycloak unreachable | Check URL and network |
---
**📄 For detailed documentation, see: LOGIN_FLOW_DOCUMENTATION.md**
