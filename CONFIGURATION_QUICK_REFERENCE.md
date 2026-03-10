# Configuration Quick Reference

## Required Environment Variables

```bash
# Mandatory - No default value
export KEYCLOAK_ADMIN_PASSWORD=YourSecurePassword123

# Optional - Have defaults
export KEYCLOAK_ADMIN=admin                    # Default: admin
export KEYCLOAK_CLIENT_ID=admin-cli            # Default: admin-cli
export KEYCLOAK_MASTER_REALM=master            # Default: master

# Already Required
export KEYCLOAK_BASE_URL=http://localhost:8080
export KEYCLOAK_REALM=your-realm
export PROJECT_MANAGER_URL=http://localhost:8088
```

## application.properties Mapping

| Property | Environment Variable | Default | Required |
|----------|---------------------|---------|----------|
| `keycloak.admin-username` | `KEYCLOAK_ADMIN` | `admin` | No |
| `keycloak.admin-password` | `KEYCLOAK_ADMIN_PASSWORD` | - | **Yes** |
| `keycloak.client-id` | `KEYCLOAK_CLIENT_ID` | `admin-cli` | No |
| `keycloak.master-realm` | `KEYCLOAK_MASTER_REALM` | `master` | No |

## Before vs After

### Before (Hardcoded)
```java
// Constants
private static final String ADMIN_CLI = "admin-cli";
private static final String MASTER_REALM = "master";

// Usage
productService.getMyRealmToken("admin", "admin123", "admin-cli", "master")
```

### After (Configurable)
```java
// Injected from properties
@Value("${keycloak.admin-username:admin}")
private String adminUsername;

@Value("${keycloak.admin-password}")
private String adminPassword;

@Value("${keycloak.client-id:admin-cli}")
private String keycloakClientId;

@Value("${keycloak.master-realm:master}")
private String masterRealm;

// Usage
productService.getMyRealmToken(adminUsername, adminPassword, keycloakClientId, masterRealm)
```

## Quick Test

```bash
# Set password
export KEYCLOAK_ADMIN_PASSWORD=admin@123

# Run application
mvn spring-boot:run

# Verify it starts without errors
```

## Docker Run

```bash
docker run -d \
  -e KEYCLOAK_BASE_URL=http://keycloak:8080 \
  -e KEYCLOAK_REALM=master \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin@123 \
  -e KEYCLOAK_CLIENT_ID=admin-cli \
  -e KEYCLOAK_MASTER_REALM=master \
  -p 8087:8087 \
  identity-service:latest
```

## Troubleshooting

### Error: "Could not resolve placeholder 'keycloak.admin-password'"
**Solution:** Set the `KEYCLOAK_ADMIN_PASSWORD` environment variable

```bash
export KEYCLOAK_ADMIN_PASSWORD=YourPassword
```

### Want to use different admin username?
```bash
export KEYCLOAK_ADMIN=myadmin
```

### Want to use different client ID?
```bash
export KEYCLOAK_CLIENT_ID=custom-admin-cli
```

### Want to use different master realm?
```bash
export KEYCLOAK_MASTER_REALM=custom-master
```

## Security Best Practices

✅ **DO:**
- Store passwords in environment variables
- Use secret managers in production (AWS Secrets Manager, HashiCorp Vault)
- Rotate credentials regularly
- Use different passwords per environment

❌ **DON'T:**
- Commit passwords to version control
- Use the same password across environments
- Share passwords in plain text
- Hardcode credentials in source code

## All Removed Hardcoded Values

| What | Where | Now Configured In |
|------|-------|------------------|
| `admin` | Username | `keycloak.admin-username` |
| `admin123` / `admin@123` | Password | `keycloak.admin-password` |
| `admin-cli` | Client ID | `keycloak.client-id` |
| `master` | Master Realm | `keycloak.master-realm` |

---

**Status:** ✅ All hardcoded values removed and externalized to configuration


