// package com.paxaris.identity_service.service;

// import lombok.extern.slf4j.Slf4j;
// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.http.*;
// import org.springframework.stereotype.Service;
// import org.springframework.web.client.RestTemplate;

// import java.util.Base64;
// import java.util.HashMap;
// import java.util.Map;

// @Slf4j
// @Service
// public class DockerHubService {

// private final RestTemplate restTemplate;
// private final String dockerHubUsername;
// private final String dockerHubPassword;
// private final String dockerHubApiUrl = "https://hub.docker.com/v2";

// public DockerHubService(
// RestTemplate restTemplate,
// @Value("${docker.hub.username}") String dockerHubUsername,
// @Value("${docker.hub.password}") String dockerHubPassword) {
// this.restTemplate = restTemplate;
// this.dockerHubUsername = dockerHubUsername;
// this.dockerHubPassword = dockerHubPassword;
// }

// /**
// * Prepares Docker Hub repository (verifies access, repository will be created
// on first push)
// * Note: Docker Hub repositories are created automatically when you push an
// image for the first time.
// * This method verifies authentication and checks if the repository already
// exists.
// * @param repositoryName The name of the repository (e.g.,
// "username/repo-name")
// * @return true if ready for push, false otherwise
// */
// public boolean createRepository(String repositoryName) {
// log.info("Preparing Docker Hub repository: {}", repositoryName);

// try {
// // Verify authentication
// authenticate();

// // Check if repository already exists
// if (repositoryExists(repositoryName)) {
// log.info("Repository {} already exists in Docker Hub", repositoryName);
// return true;
// }

// // Repository doesn't exist yet, but that's OK - it will be created on first
// push
// log.info("Repository {} will be created automatically on first push",
// repositoryName);
// return true;
// } catch (Exception e) {
// log.error("Error preparing Docker Hub repository {}: {}", repositoryName,
// e.getMessage(), e);
// throw new RuntimeException("Failed to prepare Docker Hub repository: " +
// e.getMessage(), e);
// }
// }

// /**
// * Checks if a repository exists in Docker Hub
// */
// public boolean repositoryExists(String repositoryName) {
// try {
// String url = dockerHubApiUrl + "/repositories/" + repositoryName + "/";
// HttpHeaders headers = createAuthHeaders();
// HttpEntity<Void> request = new HttpEntity<>(headers);

// ResponseEntity<String> response = restTemplate.exchange(
// url,
// HttpMethod.GET,
// request,
// String.class
// );

// return response.getStatusCode().is2xxSuccessful();
// } catch (Exception e) {
// log.debug("Repository {} does not exist or is not accessible: {}",
// repositoryName, e.getMessage());
// return false;
// }
// }

// /**
// * Creates authentication headers for Docker Hub API
// */
// private HttpHeaders createAuthHeaders() {
// HttpHeaders headers = new HttpHeaders();
// String auth = dockerHubUsername + ":" + dockerHubPassword;
// String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
// headers.set("Authorization", "Basic " + encodedAuth);
// return headers;
// }

// /**
// * Authenticates with Docker Hub and returns a token
// * Note: Docker Hub v2 API uses Basic Auth, but we can also get a token for
// some operations
// */
// public String authenticate() {
// try {
// String url = "https://hub.docker.com/v2/users/login/";

// HttpHeaders headers = new HttpHeaders();
// headers.setContentType(MediaType.APPLICATION_JSON);

// Map<String, String> body = new HashMap<>();
// body.put("username", dockerHubUsername);
// body.put("password", dockerHubPassword);

// HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);

// ResponseEntity<Map> response = restTemplate.exchange(
// url,
// HttpMethod.POST,
// request,
// Map.class
// );

// if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null)
// {
// String token = (String) response.getBody().get("token");
// log.info("Successfully authenticated with Docker Hub");
// return token;
// } else {
// throw new RuntimeException("Docker Hub authentication failed");
// }
// } catch (Exception e) {
// log.error("Error authenticating with Docker Hub: {}", e.getMessage(), e);
// throw new RuntimeException("Failed to authenticate with Docker Hub: " +
// e.getMessage(), e);
// }
// }
// }
