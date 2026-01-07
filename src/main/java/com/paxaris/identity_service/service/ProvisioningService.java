package com.paxaris.identity_service.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Comparator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.Base64;

@Service
public class ProvisioningService {

    private final String githubToken;
    private final String githubUser;
    private final String dockerHubUser;


    public ProvisioningService(
            @Value("${github.token}") String githubToken,
            @Value("${github.org}") String githubUser,
            @Value("${docker.hub.username}") String dockerHubUser
    ) {
        this.githubToken = githubToken;
        this.githubUser = githubUser;
        this.dockerHubUser = dockerHubUser;
    }



    public void provision(String repoName, MultipartFile zipFile) throws Exception {

        createRepo(repoName);

        Path tempDir = unzip(zipFile);
        uploadDirectoryToGitHub(tempDir, repoName);

        triggerBuild(repoName);

        deleteDirectory(tempDir);
    }

    // --------------------------------------------------
    // CREATE REPO
    // --------------------------------------------------
    private void createRepo(String repoName) throws IOException {

        HttpURLConnection conn = (HttpURLConnection)
                new URL("https://api.github.com/user/repos").openConnection();

        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "token " + githubToken);
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        String body = """
        { "name": "%s", "private": true }
        """.formatted(repoName);

        conn.getOutputStream().write(body.getBytes());

        if (conn.getResponseCode() != 201) {
            throw new RuntimeException("Repo creation failed");
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

        String api =
                "https://api.github.com/repos/" + githubUser + "/" + repo +
                        "/contents/" + path;

        HttpURLConnection conn = (HttpURLConnection) new URL(api).openConnection();
        conn.setRequestMethod("PUT");
        conn.setRequestProperty("Authorization", "token " + githubToken);
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
    // TRIGGER CI
    // --------------------------------------------------
    private void triggerBuild(String repo) throws IOException {

        String api =
                "https://api.github.com/repos/" + githubUser + "/" + repo +
                        "/dispatches";

        HttpURLConnection conn = (HttpURLConnection) new URL(api).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "token " + githubToken);
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        String payload = """
        { "event_type": "build-image" }
        """;

        conn.getOutputStream().write(payload.getBytes());

        if (conn.getResponseCode() != 204) {
            throw new RuntimeException("CI trigger failed");
        }
    }

    // --------------------------------------------------
    // UTIL
    // --------------------------------------------------
    private Path unzip(MultipartFile zip) throws IOException {
        // Create a temp directory to extract ZIP contents
        Path dir = Files.createTempDirectory("upload");

        try (ZipInputStream zis = new ZipInputStream(zip.getInputStream())) {
            ZipEntry entry;

            while ((entry = zis.getNextEntry()) != null) {
                // Normalize the path to prevent zip slip attacks
                Path resolvedPath = dir.resolve(entry.getName()).normalize();

                if (!resolvedPath.startsWith(dir)) {
                    // Entry is trying to escape the target directory, reject it
                    throw new IOException("Zip entry is outside of the target dir: " + entry.getName());
                }

                if (entry.isDirectory()) {
                    Files.createDirectories(resolvedPath);
                } else {
                    // Make sure parent directories exist
                    Files.createDirectories(resolvedPath.getParent());
                    // Copy file content
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
