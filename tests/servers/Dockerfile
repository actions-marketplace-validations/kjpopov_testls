FROM docker.io/library/debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
COPY server.pem server.key /
ENTRYPOINT ["openssl", "s_server", "-www", "-cert", "/server.pem", "-key", "/server.key", "-accept", "4433"]
