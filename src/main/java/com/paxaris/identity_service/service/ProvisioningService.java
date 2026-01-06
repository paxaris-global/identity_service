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

@Service
public class ProvisioningService {

    private final String githubToken;
    private final String githubOrg;

    public ProvisioningService(
            @Value("${github.token}") String githubToken,
            @Value("${github.org}") String githubOrg
    ) {
        if (githubToken == null || githubToken.isBlank()) {
            throw new IllegalStateException("GITHUB_TOKEN is missing");
        }
        if (githubOrg == null || githubOrg.isBlank()) {
            throw new IllegalStateException("GITHUB_ORG is missing");
        }
        this.githubToken = githubToken;
        this.githubOrg = githubOrg;
    }

    // =========================================================
    // ENTRY POINT
    // =========================================================
    public void provisionRepoAndPushZip(
            String realmName,
            String clientId,
            MultipartFile sourceZip
    ) {
        String repoName = realmName + "-" + clientId;

        Path extractedDir = null;

        try {
            createGitHubRepo(repoName);

            extractedDir = unzip(sourceZip);
            Path projectRoot = resolveProjectRoot(extractedDir);

            gitInitAddCommitPush(projectRoot, repoName);

            triggerCentralCIPipeline(repoName);

        } catch (Exception e) {
            throw new RuntimeException("Provisioning failed: " + e.getMessage(), e);
        } finally {
            if (extractedDir != null) {
                try {
                    deleteDirectory(extractedDir);
                } catch (IOException ignored) {}
            }
        }
    }

    // =========================================================
    // GITHUB REPO CREATION (ORG)
    // =========================================================
    private void createGitHubRepo(String repoName) throws IOException {

        String apiUrl = "https://api.github.com/orgs/" + githubOrg + "/repos";

        String payload = """
        {
          "name": "%s",
          "private": true
        }
        """.formatted(repoName);

        HttpURLConnection conn = (HttpURLConnection) new URL(apiUrl).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + githubToken);
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        conn.getOutputStream().write(payload.getBytes(StandardCharsets.UTF_8));

        if (conn.getResponseCode() != 201) {
            String error = conn.getErrorStream() != null
                    ? new String(conn.getErrorStream().readAllBytes(), StandardCharsets.UTF_8)
                    : "unknown error";
            throw new IOException("GitHub repo creation failed: " + error);
        }
    }

    // =========================================================
    // ZIP EXTRACTION
    // =========================================================
    private Path unzip(MultipartFile zipFile) throws IOException {
        Path tempDir = Files.createTempDirectory("repo-");

        try (ZipInputStream zis = new ZipInputStream(zipFile.getInputStream())) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {

                Path path = tempDir.resolve(entry.getName()).normalize();

                if (!path.startsWith(tempDir)) {
                    throw new IOException("Zip entry outside target dir: " + entry.getName());
                }

                if (entry.isDirectory()) {
                    Files.createDirectories(path);
                } else {
                    Files.createDirectories(path.getParent());
                    Files.copy(zis, path, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
        return tempDir;
    }

    /**
     * Handles ZIPs like:
     * my-project/
     *   pom.xml
     *   src/
     */
    private Path resolveProjectRoot(Path extractedDir) throws IOException {
        try (var files = Files.list(extractedDir)) {
            var list = files.toList();
            if (list.size() == 1 && Files.isDirectory(list.get(0))) {
                return list.get(0);
            }
            return extractedDir;
        }
    }

    // =========================================================
    // GIT INIT + PUSH
    // =========================================================
    private void gitInitAddCommitPush(Path repoDir, String repoName)
            throws IOException, InterruptedException {

        run(repoDir, "git", "init");
        run(repoDir, "git", "config", "user.name", "Paxaris CI");
        run(repoDir, "git", "config", "user.email", "ci@paxaris.com");
        run(repoDir, "git", "branch", "-M", "main");

        run(repoDir, "git", "remote", "add", "origin",
                "https://github.com/" + githubOrg + "/" + repoName + ".git");

        run(repoDir, "git", "add", ".");
        run(repoDir, "git", "commit", "-m", "Initial commit");

        run(repoDir, "git", "push",
                "https://x-access-token:" + githubToken +
                        "@github.com/" + githubOrg + "/" + repoName + ".git",
                "main");
    }

    private void run(Path dir, String... cmd)
            throws IOException, InterruptedException {

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir.toFile());
        pb.redirectErrorStream(true);

        Process p = pb.start();
        try (BufferedReader reader =
                     new BufferedReader(new InputStreamReader(p.getInputStream()))) {

            while (reader.readLine() != null) {}
        }

        if (p.waitFor() != 0) {
            throw new IOException("Command failed: " + String.join(" ", cmd));
        }
    }

    // =========================================================
    // TRIGGER CENTRAL CI
    // =========================================================
    private void triggerCentralCIPipeline(String repoName) throws IOException {

        String apiUrl =
                "https://api.github.com/repos/" + githubOrg + "/central-ci-repo/dispatches";

        String payload = """
        {
          "event_type": "build-image",
          "client_payload": {
            "repo": "%s/%s"
          }
        }
        """.formatted(githubOrg, repoName);

        HttpURLConnection conn = (HttpURLConnection) new URL(apiUrl).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + githubToken);
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        conn.getOutputStream().write(payload.getBytes(StandardCharsets.UTF_8));

        if (conn.getResponseCode() != 204) {
            throw new IOException("CI trigger failed: HTTP " + conn.getResponseCode());
        }
    }

    // =========================================================
    // CLEANUP
    // =========================================================
    private void deleteDirectory(Path path) throws IOException {
        Files.walk(path)
                .sorted(Comparator.reverseOrder())
                .forEach(p -> {
                    try {
                        Files.delete(p);
                    } catch (IOException ignored) {}
                });
    }
}
