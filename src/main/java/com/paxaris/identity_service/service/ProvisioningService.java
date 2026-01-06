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
    private final String githubOrg;  // can be null or empty for user repo

    public ProvisioningService(
            @Value("${github.token}") String githubToken,
            @Value("${github.org:}") String githubOrg // default empty if not set
    ) {
        if (githubToken == null || githubToken.isBlank()) {
            throw new IllegalStateException("GITHUB_TOKEN is missing");
        }
        this.githubToken = githubToken;
        this.githubOrg = (githubOrg == null || githubOrg.isBlank()) ? null : githubOrg;
    }

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

    private void createGitHubRepo(String repoName) throws IOException {
        String apiUrl;
        if (githubOrg != null) {
            // Create repo inside org
            apiUrl = "https://api.github.com/orgs/" + githubOrg + "/repos";
        } else {
            // Create repo under user account
            apiUrl = "https://api.github.com/user/repos";
        }

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

        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = conn.getResponseCode();

        if (responseCode != 201) {
            String error = "";
            try (InputStream errorStream = conn.getErrorStream()) {
                if (errorStream != null) {
                    error = new String(errorStream.readAllBytes(), StandardCharsets.UTF_8);
                }
            }
            throw new IOException("GitHub repo creation failed: HTTP " + responseCode + " - " + error);
        }
    }

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
                zis.closeEntry();
            }
        }
        return tempDir;
    }

    private Path resolveProjectRoot(Path extractedDir) throws IOException {
        try (var files = Files.list(extractedDir)) {
            var list = files.toList();
            if (list.size() == 1 && Files.isDirectory(list.get(0))) {
                return list.get(0);
            }
            return extractedDir;
        }
    }

    private void gitInitAddCommitPush(Path repoDir, String repoName)
            throws IOException, InterruptedException {

        run(repoDir, "git", "init");
        run(repoDir, "git", "config", "user.name", "Paxaris CI");
        run(repoDir, "git", "config", "user.email", "ci@paxaris.com");
        run(repoDir, "git", "branch", "-M", "main");

        String remoteUrl;
        if (githubOrg != null) {
            remoteUrl = "https://github.com/" + githubOrg + "/" + repoName + ".git";
        } else {
            // User account repo
            remoteUrl = "https://github.com/" + repoName + ".git";
        }

        run(repoDir, "git", "remote", "add", "origin", remoteUrl);

        run(repoDir, "git", "add", ".");
        run(repoDir, "git", "commit", "-m", "Initial commit");

        // Use token in push URL for authentication
        String pushUrl;
        if (githubOrg != null) {
            pushUrl = "https://x-access-token:" + githubToken + "@github.com/" + githubOrg + "/" + repoName + ".git";
        } else {
            pushUrl = "https://x-access-token:" + githubToken + "@github.com/" + repoName + ".git";
        }

        run(repoDir, "git", "push", pushUrl, "main");
    }

    private void run(Path dir, String... cmd) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir.toFile());
        pb.redirectErrorStream(true);

        Process p = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        }

        int exitCode = p.waitFor();
        if (exitCode != 0) {
            throw new IOException("Command failed (" + exitCode + "): " + String.join(" ", cmd));
        }
    }

    private void triggerCentralCIPipeline(String repoName) throws IOException {
        if (githubOrg == null) {
            // You may want to skip or adjust this for user repos, depending on your CI setup
            System.out.println("Skipping CI trigger since repo is created under user, not org.");
            return;
        }

        String apiUrl = "https://api.github.com/repos/" + githubOrg + "/central-ci-repo/dispatches";

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

        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.getBytes(StandardCharsets.UTF_8));
        }

        if (conn.getResponseCode() != 204) {
            throw new IOException("CI trigger failed: HTTP " + conn.getResponseCode());
        }
    }

    private void deleteDirectory(Path path) throws IOException {
        Files.walk(path)
                .sorted(Comparator.reverseOrder())
                .forEach(p -> {
                    try {
                        Files.delete(p);
                    } catch (IOException ignored) {
                    }
                });
    }
}
