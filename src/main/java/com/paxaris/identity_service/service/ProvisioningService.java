package com.paxaris.identity_service.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.*;
import java.util.Base64;
import java.util.Comparator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Service
public class ProvisioningService {

    private final String githubToken;
    private final String githubOrg;

    public ProvisioningService(
            @Value("${github.token}") String githubToken,
            @Value("${github.org}") String githubOrg
    ) {
        this.githubToken = githubToken;
        this.githubOrg = githubOrg;
    }

    public void provision(String repoName, MultipartFile zipFile) throws Exception {

        createRepo(repoName);

        Path tempDir = unzip(zipFile);
        uploadDirectoryToGitHub(tempDir, repoName);

        triggerBuild(repoName);

        deleteDirectory(tempDir);
    }

    // --------------------------------------------------
    // CREATE GITHUB REPO
    // --------------------------------------------------
    private void createRepo(String repoName) throws IOException {

        String apiUrl = "https://api.github.com/orgs/" + githubOrg + "/repos";

        HttpURLConnection conn = (HttpURLConnection)
                new URL(apiUrl).openConnection();

        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + githubToken);
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        String body = """
    {
      "name": "%s",
      "private": true,
      "auto_init": true
    }
    """.formatted(repoName);

        conn.getOutputStream().write(body.getBytes());

        int responseCode = conn.getResponseCode();

        if (responseCode != 201) {
            throw new RuntimeException("GitHub org repo creation failed. HTTP " + responseCode);
        }
    }


    // --------------------------------------------------
    // UPLOAD FILES
    // --------------------------------------------------
    private void uploadDirectoryToGitHub(Path root, String repo) throws Exception {
        Files.walk(root)
                .filter(Files::isRegularFile)
                .forEach(file -> {
                    try {
                        uploadFile(root, file, repo);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    private void uploadFile(Path root, Path file, String repo) throws Exception {

        String path = root.relativize(file).toString().replace("\\", "/");
        byte[] content = Files.readAllBytes(file);
        String base64 = Base64.getEncoder().encodeToString(content);

        String api = "https://api.github.com/repos/" + githubOrg + "/" + repo + "/contents/" + path;

        HttpURLConnection conn = (HttpURLConnection) new URL(api).openConnection();
        conn.setRequestMethod("PUT");
        conn.setRequestProperty("Authorization", "Bearer " + githubToken);
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        String payload = """
        {
          "message": "initial commit",
          "content": "%s"
        }
        """.formatted(base64);

        conn.getOutputStream().write(payload.getBytes());

        if (conn.getResponseCode() >= 300) {
            throw new RuntimeException("File upload failed: " + path);
        }
    }

    // --------------------------------------------------
    // TRIGGER GITHUB ACTION
    // --------------------------------------------------
    private void triggerBuild(String repo) throws IOException {

        String api = "https://api.github.com/repos/" + githubOrg + "/" + repo + "/dispatches";

        HttpURLConnection conn = (HttpURLConnection) new URL(api).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + githubToken);
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        conn.getOutputStream().write("{ \"event_type\": \"build-image\" }".getBytes());

        if (conn.getResponseCode() != 204) {
            throw new RuntimeException("GitHub Action trigger failed");
        }
    }

    // --------------------------------------------------
    // UTIL
    // --------------------------------------------------
    private Path unzip(MultipartFile zip) throws IOException {

        Path dir = Files.createTempDirectory("upload");

        try (ZipInputStream zis = new ZipInputStream(zip.getInputStream())) {


            ZipEntry entry;

            while ((entry = zis.getNextEntry()) != null) {
                Path resolvedPath = dir.resolve(entry.getName()).normalize();

                if (!resolvedPath.startsWith(dir)) {
                    throw new IOException("Invalid zip entry");
                }

                if (entry.isDirectory()) {
                    Files.createDirectories(resolvedPath);
                } else {
                    Files.createDirectories(resolvedPath.getParent());
                    Files.copy(zis, resolvedPath, StandardCopyOption.REPLACE_EXISTING);
                }
                zis.closeEntry();
            }
        }
        return dir;
    }

    private void deleteDirectory(Path path) throws IOException {
        Files.walk(path)
                .sorted(Comparator.reverseOrder())
                .forEach(p -> {
                    try { Files.delete(p); } catch (Exception ignored) {}
                });
    }
}
