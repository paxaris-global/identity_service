FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app

COPY pom.xml ./
COPY src ./src

RUN mvn -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app

RUN apt-get update \
    && apt-get install -y git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/identity_service-0.0.1-SNAPSHOT.jar /app/identity_service.jar

EXPOSE 8087
ENTRYPOINT ["java", "-jar", "/app/identity_service.jar"]
