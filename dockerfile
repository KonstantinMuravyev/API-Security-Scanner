FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests -Dmaven.test.skip=true

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/target/api-security-scanner-1.0.0.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]