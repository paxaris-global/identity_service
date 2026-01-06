FROM openjdk:21

# Install git (update package lists and clean up to reduce image size)
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# Copy the built jar file into the container
COPY target/identity_service-0.0.1-SNAPSHOT.jar /app/identity_service.jar

# Default command to run your application
ENTRYPOINT ["java", "-jar", "/app/identity_service.jar"]
