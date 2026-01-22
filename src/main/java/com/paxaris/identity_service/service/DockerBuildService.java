// package com.paxaris.identity_service.service;

// import lombok.extern.slf4j.Slf4j;
// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.stereotype.Service;

// import java.io.*;
// import java.nio.file.Files;
// import java.nio.file.Path;
// import java.nio.file.Paths;
// import java.nio.file.StandardOpenOption;
// import java.util.concurrent.TimeUnit;

// @Slf4j
// @Service
// public class DockerBuildService {

// private final String dockerHubUsername;
// private final String dockerHubPassword;

// public DockerBuildService(
// @Value("${docker.hub.username}") String dockerHubUsername,
// @Value("${docker.hub.password}") String dockerHubPassword) {
// this.dockerHubUsername = dockerHubUsername;
// this.dockerHubPassword = dockerHubPassword;
// }

// /**
// *
// * Builds a Docker image from the source code directory
// * @param sourceCodePath Path to the extracted source code
// * @param imageName Full Docker image name (e.g., "username/repo-name:tag")
// * @return true if build successful, false otherwise
// */
// public boolean buildDockerImage(Path sourceCodePath, String imageName) {
// log.info("Building Docker image: {} from path: {}", imageName,
// sourceCodePath);

// try {
// // Ensure Dockerfile exists, create one if it doesn't
// Path dockerfilePath = sourceCodePath.resolve("Dockerfile");
// if (!Files.exists(dockerfilePath)) {
// log.info("Dockerfile not found, generating default Dockerfile");
// generateDefaultDockerfile(dockerfilePath);
// }

// // Build Docker image
// ProcessBuilder processBuilder = new ProcessBuilder(
// "docker", "build",
// "-t", imageName,
// sourceCodePath.toString()
// );

// processBuilder.redirectErrorStream(true);
// Process process = processBuilder.start();

// // Log build output
// try (BufferedReader reader = new BufferedReader(
// new InputStreamReader(process.getInputStream()))) {
// String line;
// while ((line = reader.readLine()) != null) {
// log.debug("Docker build: {}", line);
// }
// }

// boolean finished = process.waitFor(30, TimeUnit.MINUTES);
// if (!finished) {
// process.destroyForcibly();
// throw new RuntimeException("Docker build timed out after 30 minutes");
// }

// int exitCode = process.exitValue();
// if (exitCode == 0) {
// log.info("Successfully built Docker image: {}", imageName);
// return true;
// } else {
// log.error("Docker build failed with exit code: {}", exitCode);
// return false;
// }
// } catch (Exception e) {
// log.error("Error building Docker image {}: {}", imageName, e.getMessage(),
// e);
// throw new RuntimeException("Failed to build Docker image: " + e.getMessage(),
// e);
// }
// }

// /**
// * Pushes a Docker image to Docker Hub
// * @param imageName Full Docker image name (e.g., "username/repo-name:tag")
// * @return true if push successful, false otherwise
// */
// public boolean pushDockerImage(String imageName) {
// log.info("Pushing Docker image to Docker Hub: {}", imageName);

// try {
// // Login to Docker Hub first
// if (!loginToDockerHub()) {
// throw new RuntimeException("Failed to login to Docker Hub");
// }

// // Push the image
// ProcessBuilder processBuilder = new ProcessBuilder(
// "docker", "push", imageName
// );

// processBuilder.redirectErrorStream(true);
// Process process = processBuilder.start();

// // Log push output
// try (BufferedReader reader = new BufferedReader(
// new InputStreamReader(process.getInputStream()))) {
// String line;
// while ((line = reader.readLine()) != null) {
// log.debug("Docker push: {}", line);
// }
// }

// boolean finished = process.waitFor(30, TimeUnit.MINUTES);
// if (!finished) {
// process.destroyForcibly();
// throw new RuntimeException("Docker push timed out after 30 minutes");
// }

// int exitCode = process.exitValue();
// if (exitCode == 0) {
// log.info("Successfully pushed Docker image to Docker Hub: {}", imageName);
// return true;
// } else {
// log.error("Docker push failed with exit code: {}", exitCode);
// return false;
// }
// } catch (Exception e) {
// log.error("Error pushing Docker image {}: {}", imageName, e.getMessage(), e);
// throw new RuntimeException("Failed to push Docker image: " + e.getMessage(),
// e);
// }
// }

// /**
// * Generates a default Dockerfile if one doesn't exist
// */
// private void generateDefaultDockerfile(Path dockerfilePath) throws
// IOException {
// log.info("Generating default Dockerfile at: {}", dockerfilePath);

// // Try to detect the application type and generate appropriate Dockerfile
// Path parentDir = dockerfilePath.getParent();

// // Check for common application types
// String dockerfileContent;

// if (Files.exists(parentDir.resolve("pom.xml"))) {
// // Maven Java application
// dockerfileContent = """
// FROM eclipse-temurin:21-jdk
// WORKDIR /app
// COPY . .
// RUN ./mvnw clean package -DskipTests
// EXPOSE 8080
// ENTRYPOINT ["java", "-jar", "target/*.jar"]
// """;
// } else if (Files.exists(parentDir.resolve("package.json"))) {
// // Node.js application
// dockerfileContent = """
// FROM node:20-alpine
// WORKDIR /app
// COPY package*.json ./
// RUN npm install
// COPY . .
// EXPOSE 3000
// CMD ["npm", "start"]
// """;
// } else if (Files.exists(parentDir.resolve("requirements.txt"))) {
// // Python application
// dockerfileContent = """
// FROM python:3.11-slim
// WORKDIR /app
// COPY requirements.txt .
// RUN pip install --no-cache-dir -r requirements.txt
// COPY . .
// EXPOSE 8000
// CMD ["python", "app.py"]
// """;
// } else {
// // Generic Dockerfile
// dockerfileContent = """
// FROM ubuntu:22.04
// WORKDIR /app
// COPY . .
// EXPOSE 8080
// CMD ["echo", "Please customize this Dockerfile for your application"]
// """;
// }

// Files.writeString(dockerfilePath, dockerfileContent,
// StandardOpenOption.CREATE);
// log.info("Generated default Dockerfile for detected application type");
// }

// /**
// * Logs in to Docker Hub using docker login command
// */
// private boolean loginToDockerHub() {
// log.info("Logging in to Docker Hub");

// try {
// ProcessBuilder processBuilder = new ProcessBuilder(
// "docker", "login",
// "-u", dockerHubUsername,
// "-p", dockerHubPassword,
// "docker.io"
// );

// processBuilder.redirectErrorStream(true);
// Process process = processBuilder.start();

// // Read output
// try (BufferedReader reader = new BufferedReader(
// new InputStreamReader(process.getInputStream()))) {
// String line;
// while ((line = reader.readLine()) != null) {
// log.debug("Docker login: {}", line);
// }
// }

// boolean finished = process.waitFor(1, TimeUnit.MINUTES);
// if (!finished) {
// process.destroyForcibly();
// return false;
// }

// int exitCode = process.exitValue();
// if (exitCode == 0) {
// log.info("Successfully logged in to Docker Hub");
// return true;
// } else {
// log.error("Docker login failed with exit code: {}", exitCode);
// return false;
// }
// } catch (Exception e) {
// log.error("Error logging in to Docker Hub: {}", e.getMessage(), e);
// return false;
// }
// }

// /**
// * Builds and pushes a Docker image in one operation
// */
// public boolean buildAndPushImage(Path sourceCodePath, String imageName) {
// log.info("Building and pushing Docker image: {}", imageName);

// if (!buildDockerImage(sourceCodePath, imageName)) {
// return false;
// }

// return pushDockerImage(imageName);
// }
// }
