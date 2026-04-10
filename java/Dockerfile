FROM eclipse-temurin:17-jdk-alpine AS build

WORKDIR /app
COPY src/ src/

# Compile
RUN mkdir -p out && \
    javac -d out $(find src -name "*.java")

FROM eclipse-temurin:17-jre-alpine

WORKDIR /app
COPY --from=build /app/out .

ENV PORT=3000

EXPOSE 3000

CMD ["java", "io.monime.exchange.ExchangeHandler"]
