FROM debian:trixie@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c

ENV DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates openssl libnss3-tools iproute2 util-linux xz-utils tini \
    && groupadd --gid 1000 jail && useradd --uid 1000 --gid 1000 --create-home jail
RUN case "$TARGETARCH" in \
      amd64) node_arch=x64; sha=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6 ;; \
      arm64) node_arch=arm64; sha=6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2 ;; \
      *) exit 2 ;; \
    esac \
    && curl -fSL "https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-$node_arch.tar.xz" -o /tmp/node.tar.xz \
    && printf '%s  /tmp/node.tar.xz\n' "$sha" | sha256sum --check \
    && tar -xJf /tmp/node.tar.xz --strip-components=1 -C /usr/local \
    && rm /tmp/node.tar.xz \
    && test "$(node --version)" = v24.21.0
WORKDIR /opt/playwright
RUN npm install --save-exact playwright@1.63.0 \
    && PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright npx playwright install --with-deps chromium \
    && find /opt/ms-playwright -path '*/chrome-linux*/chrome' -type f > /etc/vm-browser-path \
    && test "$(wc -l < /etc/vm-browser-path)" -eq 1 \
    && ln -s "$(cat /etc/vm-browser-path)" /usr/local/bin/chromium \
    && mkdir -p /home/jail/.cache /scratch /newroot /oldroot /artifacts \
    && ln -s /opt/ms-playwright /home/jail/.cache/ms-playwright \
    && ln -s /opt/playwright/node_modules /home/jail/node_modules \
    && chown -R 1000:1000 /home/jail /artifacts \
    && npm cache clean --force && rm -rf /var/lib/apt/lists/* /root/.cache
COPY --chmod=0755 vm-guest-agent /usr/local/bin/vm-guest-agent
COPY --chmod=0755 vm-init /sbin/vm-init
COPY --chmod=0755 browse /usr/local/bin/browse
WORKDIR /home/jail
ENTRYPOINT ["/sbin/vm-init"]
