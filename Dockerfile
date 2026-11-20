# Multi-stage build: web console, then the server with the console embedded.
FROM node:24-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
COPY --from=web /web/dist web/dist
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /var/lib/picacho --create-home picacho
COPY --from=build /src/target/release/picacho-server /usr/local/bin/picacho-server
USER picacho
WORKDIR /var/lib/picacho
ENV PICACHO_CONFIG=/etc/picacho/config.toml
EXPOSE 25 80 143 465 587 993 4190 8080
VOLUME ["/var/lib/picacho"]
ENTRYPOINT ["picacho-server"]
