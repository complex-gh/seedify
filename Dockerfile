# Multi-platform Dockerfile for dockers_v2
# GoReleaser places binaries in platform-specific directories (e.g., linux/amd64/seedify)
FROM gcr.io/distroless/static

ARG TARGETOS
ARG TARGETARCH

COPY ${TARGETOS}/${TARGETARCH}/seedify /usr/local/bin/seedify

ENTRYPOINT [ "/usr/local/bin/seedify" ]
