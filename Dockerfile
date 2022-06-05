FROM localhost:31102/service84/service-builder:latest AS service-builder
WORKDIR /app
COPY .openapi-generator-ignore .openapi-generator-ignore
COPY LICENSE LICENSE
COPY NOTICE NOTICE
COPY version.gradle version.gradle
COPY build.gradle build.gradle
RUN gradle --console verbose downloadDependencies
COPY src src
RUN gradle --console verbose build

FROM localhost:31102/library/openjdk:11-jre AS service-runner
WORKDIR /app
COPY --from=service-builder /app/build/libs/app.jar ./app.jar

CMD ["java","-jar","-Dserver.port=80","/app/app.jar"]
