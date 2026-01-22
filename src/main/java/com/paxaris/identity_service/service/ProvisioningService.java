package com.paxaris.identity_service.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

@Slf4j
@Service
public class ProvisioningService {

    private final String githubToken;
    private final String githubOrg;
    private final ObjectMapper objectMapper;

    public ProvisioningService(
            @Value("${github.token}") String githubToken,
            @Value("${github.org}") String githubOrg) {
        this.githubToken = githubToken;
        this.githubOrg = githubOrg;
        this.objectMapper = new ObjectMapper();
    }

    public String getGithubToken() {
        return githubToken;
    }

    public String getGithubOrg() {
        return githubOrg;
    }

    /**
     * Entry point for provisioning: Creates repo, unzips file, and uploads in one
     * commit.
     */
    public Path provision(String repoName, MultipartFile zipFile) throws Exception {
        createRepo(repoName);
        Path tempDir = unzip(zipFile);
        uploadDirectoryToGitHub(tempDir, repoName);
        return tempDir;
    }

    public static String generateRepositoryName(String realmName, String adminUsername, String clientName) {
        String adminPart = adminUsername != null ? adminUsername : "admin";
        return String.format("%s-%s-%s", realmName, adminPart, clientName).toLowerCase();
    }

    // --------------------------------------------------
    // CREATE GITHUB REPO
    // --------------------------------------------------
    public void createRepo(String repoName) throws IOException {
        validateConfig();

        String apiUrl = "https://api.github.com/orgs/" + githubOrg + "/repos";

        // auto_init: true is required to create the 'main' branch so we can update it
        // later
        String body = """
                {
                  "name": "%s",
                  "private": true,
                  "auto_init": true
                }
                """.formatted(repoName);

        sendRequest("POST", apiUrl, body);
    }

    // --------------------------------------------------
    // UPLOAD FILES (THE "ONE COMMIT" LOGIC)
    // --------------------------------------------------
    public void uploadDirectoryToGitHub(Path root, String repo) throws Exception {
        List<Map<String, Object>> treeEntries = new ArrayList<>();

        // 1. Walk the directory and prepare Tree Entries
        Files.walk(root)
                .filter(Files::isRegularFile)
                .forEach(file -> {
                    try {
                        String path = root.relativize(file).toString().replace("\\", "/");
                        byte[] content = Files.readAllBytes(file);

                        Map<String, Object> entry = new HashMap<>();
                        entry.put("path", path);
                        entry.put("mode", "100644");
                        entry.put("type", "blob");
                        entry.put("content", new String(content, StandardCharsets.UTF_8));

                        treeEntries.add(entry);
                    } catch (IOException e) {
                        throw new RuntimeException("Error reading file for GitHub upload: " + file, e);
                    }
                });

        if (treeEntries.isEmpty())
            return;

        // 2. Create a Git Tree
        Map<String, Object> treeMap = Map.of("tree", treeEntries);
        JsonNode treeRes = sendRequest("POST", "https://api.github.com/repos/" + githubOrg + "/" + repo + "/git/trees",
                objectMapper.writeValueAsString(treeMap));
        String treeSha = treeRes.get("sha").asText();

        // 3. Create a Commit
        Map<String, Object> commitMap = Map.of(
                "message", "Initial project upload",
                "tree", treeSha);
        JsonNode commitRes = sendRequest("POST",
                "https://api.github.com/repos/" + githubOrg + "/" + repo + "/git/commits",
                objectMapper.writeValueAsString(commitMap));
        String commitSha = commitRes.get("sha").asText();

        // 4. Update Main Branch Reference
        Map<String, Object> refMap = Map.of("sha", commitSha, "force", true);
        sendRequest("PATCH", "https://api.github.com/repos/" + githubOrg + "/" + repo + "/git/refs/heads/main",
                objectMapper.writeValueAsString(refMap));

        log.info("Successfully pushed all files to {}/{} in a single commit: {}", githubOrg, repo, commitSha);
    }

    // --------------------------------------------------
    // GENERIC HTTP HELPER
    // --------------------------------------------------
    private JsonNode sendRequest(String method, String urlStr, String jsonBody) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setRequestProperty("Authorization", "Bearer " + githubToken);
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        if (jsonBody != null) {
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            }
        }

        int responseCode = conn.getResponseCode();
        if (responseCode >= 300) {
            String errorResponse = "";
            try (java.io.InputStream is = conn.getErrorStream()) {
                if (is != null)
                    errorResponse = new String(is.readAllBytes());
            }
            throw new RuntimeException("GitHub API error (" + responseCode + ") at " + urlStr + ": " + errorResponse);
        }

        return objectMapper.readTree(conn.getInputStream());
    }

    private void validateConfig() {
        if (githubToken == null || githubToken.isEmpty())
            throw new IllegalStateException("GITHUB_TOKEN missing");
        if (githubOrg == null || githubOrg.isEmpty())
            throw new IllegalStateException("GITHUB_ORG missing");
    }

    // --------------------------------------------------
    // ZIP UTIL (Using Apache Commons for better compatibility)
    // --------------------------------------------------
    private Path unzip(MultipartFile zipFile) throws IOException {
        Path extractPath = Files.createTempDirectory("upload-extract-");

        try (ZipArchiveInputStream zis = new ZipArchiveInputStream(zipFile.getInputStream())) {
            ZipArchiveEntry entry;
            while ((entry = zis.getNextZipEntry()) != null) {
                Path resolvedPath = extractPath.resolve(entry.getName()).normalize();
                if (!resolvedPath.startsWith(extractPath)) {
                    throw new IOException("Zip Slip security violation: " + entry.getName());
                }

                if (entry.isDirectory()) {
                    Files.createDirectories(resolvedPath);
                } else {
                    Files.createDirectories(resolvedPath.getParent());
                    Files.copy(zis, resolvedPath, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
        return extractPath;
    }
}