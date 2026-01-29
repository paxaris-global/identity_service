package com.paxaris.identity_service.service;

import com.paxaris.identity_service.dto.AssignRoleRequest;
import com.paxaris.identity_service.dto.RoleCreationRequest;
import com.paxaris.identity_service.dto.RoleRequest;
import com.paxaris.identity_service.dto.SignupRequest;
import com.paxaris.identity_service.dto.SignupStatus;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

public interface KeycloakClientService {
        
        String getMasterTokenInternally();
        // Token operations
        Map<String, Object> getMyRealmToken(String username, String password, String clientId, String realm);

        boolean validateToken(String realm, String token);

        Map<String, Object> getRealmToken(String realm,
                        String username,
                        String password,
                        String clientId,
                        String clientSecret);

        // Realm operations
        void createRealm(String realmName, String token);

        List<Map<String, Object>> getAllRealms(String token);

        // Client operations
        String createClient(String realm, String clientId, boolean isPublicClient, String token);

        List<Map<String, Object>> getAllClients(String realm, String token);

        String getClientSecret(String realm, String clientId, String token);

        String getClientUUID(String realm, String clientName, String token);

        String getClientId(String realm, String clientName, String token);

        // User operations
        String createUser(String realm, String token, Map<String, Object> userPayload);

        List<Map<String, Object>> getAllUsers(String realm, String token);

        // Role operations
        void createClientRoles(String realm, String clientName, List<RoleCreationRequest> roleRequests, String token);

        void createRealmRole(String realm, String roleName, String clientId, String token);

        boolean createRole(String realm, String clientUUID, RoleCreationRequest role, String token);

        boolean updateRole(String realm, String clientUUID, String roleName, RoleCreationRequest role, String token);

        boolean deleteRole(String realm, String clientUUID, String roleName, String token);

        List<Map<String, Object>> getAllRoles(String realm, String clientId, String token);

        // Role assignment operations

        void assignClientRolesByName(
                        String realm,
                        String username,
                        String clientName,
                        String token,
                        List<AssignRoleRequest> roles);

        // Signup operation
        SignupStatus signup(SignupRequest request, MultipartFile sourceZip);

        // get all clients
        List<Map<String, Object>> getClientRoles(String realm, String clientName, String token);
}
