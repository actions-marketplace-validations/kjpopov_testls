FROM docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
# Run unprivileged: 4433 needs no root, and only the server user may read the key.
COPY --chown=nobody:nogroup --chmod=0400 server.pem server.key /
USER nobody
ENTRYPOINT ["openssl", "s_server", "-www", "-cert", "/server.pem", "-key", "/server.key", "-accept", "4433"]
