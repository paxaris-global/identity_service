package com.paxaris.identity_service.service;

import com.paxaris.identity_service.dto.AssignRoleRequest;
import com.paxaris.identity_service.dto.RoleCreationRequest;
import com.paxaris.identity_service.dto.RoleRequest;
import com.paxaris.identity_service.dto.SignupRequest;
import com.paxaris.identity_service.dto.SignupStatus;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

public interface KeycloakProductService {

        String getMasterTokenInternally();

        // Token operations
        Map<String, Object> getMyRealmToken(String username, String password, String productId, String realm);

        // Product redirect URL
        String getProductRedirectUrl(String realm, String productId);

        boolean validateToken(String realm, String token);

        Map<String, Object> getRealmToken(String realm,
                        String username,
                        String password,
                        String productId,
                        String clientSecret);

        // Realm operations
        void createRealm(String realmName, String token);

        List<Map<String, Object>> getAllRealms(String token);

        // Product operations
        String createProduct(
                String realm,
                String productId,
                boolean isPublicClient,
                String token,
                MultipartFile backendZip,
                MultipartFile frontendZip,
                String frontendBaseUrl,
                SignupStatus status,
                String adminUsername
        );

        List<Map<String, Object>> getAllProducts(String realm, String token);

        String getProductSecret(String realm, String productId, String token);

        String getProductUUID(String realm, String productName, String token);

        String getProductId(String realm, String productName, String token);

        // User operations
        String createUser(String realm, String token, Map<String, Object> userPayload);

        List<Map<String, Object>> getAllUsers(String realm, String token);

        // Role operations
        void createProductRoles(String realm, String productName, List<RoleCreationRequest> roleRequests, String token);

        void createRealmRole(String realm, String roleName, String productId, String token);

        boolean createRole(String realm, String productUUID, RoleCreationRequest role, String token);

        boolean updateRole(String realm, String productUUID, String roleName, RoleCreationRequest role, String token);

        void deleteProductRole(String realm, String productName, String roleName, String token);

        List<Map<String, Object>> getAllRoles(String realm, String productId, String token);

        // Role assignment operations
        void assignProductRolesByName(
                        String realm,
                        String username,
                        String productName,
                        String token,
                        List<AssignRoleRequest> roles);

        // Signup operation
        SignupStatus signup(String realmName, String adminPassword);

        // get all product roles
        List<Map<String, Object>> getProductRoles(String realm, String productName, String token);

        // update user
        void updateUser(
                        String realm,
                        String username,
                        String token,
                        Map<String, Object> userPayload
                );

        // update the user product role
        void updateUserProductRoles(
                String realm,
                String username,
                String productName,
                String oldRole,
                String newRole,
                String token
        );

        void deleteUserProductRole(
                String realm,
                String username,
                String productName,
                String roleName,
                String token
        );

        void deleteUser(
                String realm,
                String username,
                String token
        );
}

