FROM docker.io/library/debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/* \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout /key.pem -out /cert.pem -subj /CN=localhost \
      -addext subjectAltName=DNS:localhost
ENTRYPOINT ["openssl", "s_server", "-www", "-cert", "/cert.pem", "-key", "/key.pem", "-accept", "4433"]
