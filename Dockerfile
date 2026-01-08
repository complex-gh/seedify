FROM gcr.io/distroless/static
COPY seedify /usr/local/bin/seedify
ENTRYPOINT [ "/usr/local/bin/seedify" ]
