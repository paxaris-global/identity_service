FROM eclipse-temurin:17-jdk

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY target/identity_service-0.0.1-SNAPSHOT.jar identity-service.jar

ENTRYPOINT ["java", "-jar", "identity-service.jar"]
