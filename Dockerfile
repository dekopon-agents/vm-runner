FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl iproute2 nftables e2fsprogs \
    && case "$TARGETARCH" in \
       amd64) arch=x86_64; sha=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558 ;; \
       arm64) arch=aarch64; sha=e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256 ;; \
       *) exit 2 ;; esac \
    && curl -fL "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-${arch}.tgz" -o /tmp/firecracker.tgz \
    && echo "$sha  /tmp/firecracker.tgz" | sha256sum -c - \
    && tar -xzf /tmp/firecracker.tgz -C /tmp \
    && install -m 0755 "/tmp/release-v1.17.0-${arch}/firecracker-v1.17.0-${arch}" /usr/local/bin/firecracker \
    && rm -rf /tmp/firecracker.tgz /tmp/release-v1.17.0-* /var/lib/apt/lists/*
COPY --chmod=0755 vm-runnerd /usr/local/bin/vm-runnerd
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/vm-runnerd"]
