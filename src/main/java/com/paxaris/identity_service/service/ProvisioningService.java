package com.paxaris.identity_service.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
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

    public void provisionRepoAndPushZip(
            String realmName,
            String clientId,
            MultipartFile zipFile
    ) {

        String repoName = realmName + "-" + clientId;

        try {
            createGitHubRepo(repoName);
            Path tempDir = unzip(zipFile);
            gitInitAddCommitPush(tempDir, repoName);
            deleteDirectory(tempDir);
        } catch (Exception e) {
            throw new RuntimeException("Provisioning failed: " + e.getMessage(), e);
        }
    }

    private void createGitHubRepo(String repoName) throws IOException {
        String apiUrl = "https://api.github.com/user/repos"; // or org repos if org

        String payload = """
        {
          "name": "%s",
          "private": true
        }
        """.formatted(repoName);

        HttpURLConnection conn = (HttpURLConnection) new URL(apiUrl).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "token " + githubToken);
        conn.setRequestProperty("Accept", "application/vnd.github+json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.getBytes(StandardCharsets.UTF_8));
        }

        int responseCode = conn.getResponseCode();
        System.out.println("GitHub API response code: " + responseCode);

        if (responseCode != 201) {
            InputStream errorStream = conn.getErrorStream();
            String errorMsg = "";
            if (errorStream != null) {
                errorMsg = new String(errorStream.readAllBytes(), StandardCharsets.UTF_8);
            }
            System.out.println("GitHub API error: " + errorMsg);
            throw new IOException("GitHub repo creation failed: HTTP " + responseCode + " - " + errorMsg);
        }
    }

    private Path unzip(MultipartFile zipFile) throws IOException {
        Path tempDir = Files.createTempDirectory("repo-");

        try (ZipInputStream zis = new ZipInputStream(zipFile.getInputStream())) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path path = tempDir.resolve(entry.getName());
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

    private void deleteDirectory(Path path) throws IOException {
        Files.walk(path)
                .sorted((a, b) -> b.compareTo(a))
                .forEach(p -> {
                    try {
                        Files.delete(p);
                    } catch (IOException ignored) {}
                });
    }
}
