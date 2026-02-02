package com.paxaris.identity_service.service;

import com.paxaris.identity_service.dto.AssignRoleRequest;
import com.paxaris.identity_service.dto.RoleCreationRequest;
import com.paxaris.identity_service.dto.SignupRequest;
import com.paxaris.identity_service.dto.SignupStatus;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

public interface KeycloakProductService {

        String getMasterTokenInternally();

        // Token operations
        Map<String, Object> getMyRealmToken(String username, String password, String clientId, String realm);

        boolean validateToken(String realm, String token);

        // Realm operations
        void createRealm(String realmName, String token);

        List<Map<String, Object>> getAllRealms(String token);

        // Client (Product) operations
        String createProduct(String realm, String clientId, boolean isPublicClient, String token);

        List<Map<String, Object>> getAllProducts(String realm, String token);

        String getProductUUID(String realm, String clientName, String token);

        String getProductId(String realm, String clientName, String token);

        // User operations
        String createUser(String realm, String token, Map<String, Object> userPayload);

        List<Map<String, Object>> getAllUsers(String realm, String token);

        // Role operations
        void createProductRoles(String realm, String clientName, List<RoleCreationRequest> roleRequests, String token);

        boolean updateRole(String realm, String clientUUID, String roleName, RoleCreationRequest role, String token);

        boolean deleteProductRole(String realm, String productUUID, String roleName, String token);


        // Role assignment operations
        void assignProductRolesByName(
                String realm,
                String username,
                String clientName,
                String token,
                List<AssignRoleRequest> roles);

        // Signup operation
        SignupStatus signup(SignupRequest request, MultipartFile sourceZip);

        // Get roles for a client (product)
        List<Map<String, Object>> getProductRoles(String realm, String clientName, String token);
}
