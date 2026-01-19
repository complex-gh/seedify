# Multi-platform Dockerfile for dockers_v2
# GoReleaser places binaries in platform-specific directories
FROM gcr.io/distroless/static

ARG TARGETPLATFORM
COPY seedify /usr/local/bin/seedify

ENTRYPOINT [ "/usr/local/bin/seedify" ]
