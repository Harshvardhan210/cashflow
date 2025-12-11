# ------------ Stage 1: Build JAR -------------
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app

# Copy only pom.xml first (speed up dependency caching)
COPY pom.xml .
RUN mvn dependency:go-offline

# Now copy source code
COPY src ./src

# Build jar
RUN mvn clean package -DskipTests


# ------------ Stage 2: Run App ---------------
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Copy final jar
COPY --from=build /app/target/*.jar app.jar

# Render exposes the port dynamically, use $PORT
EXPOSE 8080
ENV JAVA_OPTS=""

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
