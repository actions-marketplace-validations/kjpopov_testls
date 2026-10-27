# Release image: the static musl binary from the release build on distroless
# (CA certificates for --system-roots, no shell, unprivileged user 65532).
# The build context holds one binary per architecture as ARCH/testls
# (amd64, arm64); see the container job in .github/workflows/release.yml.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG TARGETARCH
COPY --chmod=755 ${TARGETARCH}/testls /usr/local/bin/testls
LABEL org.opencontainers.image.source="https://github.com/kjpopov/testls" \
      org.opencontainers.image.description="TLS/SSL scanner for the web era, inspired by testssl.sh." \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
ENTRYPOINT ["/usr/local/bin/testls"]
