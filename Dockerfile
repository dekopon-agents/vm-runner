FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0755 vm-runnerd /usr/local/bin/vm-runnerd
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/vm-runnerd"]
