FROM debian:trixie@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c

ENV DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates openssl libnss3-tools iproute2 util-linux xz-utils tini \
    python3 jq ripgrep zip unzip poppler-utils \
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
# Official uv GNU/Linux archives contain uv and uvx in one target-named directory.
# Ship only uv, behind an exec-env-safe wrapper; no pip or python3-venv package.
RUN case "$TARGETARCH" in \
      amd64) uv_arch=x86_64; sha=23f02075b652bb1df64178cfae41b5caf160822e720e2663568f3f5d63bc52c0 ;; \
      arm64) uv_arch=aarch64; sha=030b69227b40af8c1981b7301793dc66e71ed3c796ea8688209dd268bd91ec51 ;; \
      *) exit 2 ;; \
    esac \
    && curl -fSL "https://github.com/astral-sh/uv/releases/download/0.12.21/uv-$uv_arch-unknown-linux-gnu.tar.gz" -o /tmp/uv.tar.gz \
    && printf '%s  /tmp/uv.tar.gz\n' "$sha" | sha256sum --check \
    && tar -xzf /tmp/uv.tar.gz -C /tmp "uv-$uv_arch-unknown-linux-gnu/uv" \
    && install -m 0755 "/tmp/uv-$uv_arch-unknown-linux-gnu/uv" /usr/local/bin/uv-native \
    && rm -rf /tmp/uv.tar.gz "/tmp/uv-$uv_arch-unknown-linux-gnu" \
    && test "$(/usr/local/bin/uv-native --version)" = 'uv 0.12.21'
COPY --chmod=0755 uv /usr/local/bin/uv
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
# v0.38.1 npm postinstall selects these same native release binaries. No AB browser install.
RUN case "$TARGETARCH" in \
      amd64) ab_arch=x64; sha=5100149a1903211c889de4e545bf36d90803740cea4f99aa22651649f9205ea1 ;; \
      arm64) ab_arch=arm64; sha=937b315ee0761e8a62f7950ddcfef9b3d3d8e8d5eb9c9d2bf9e23e5725664511 ;; \
      *) exit 2 ;; \
    esac \
    && curl -fSL "https://github.com/vercel-labs/agent-browser/releases/download/v0.38.1/agent-browser-linux-$ab_arch" -o /usr/local/bin/agent-browser-native \
    && printf '%s  /usr/local/bin/agent-browser-native\n' "$sha" | sha256sum --check \
    && chmod 0755 /usr/local/bin/agent-browser-native \
    && test "$(/usr/local/bin/agent-browser-native --version)" = 'agent-browser 0.38.1'
COPY --chmod=0755 agent-browser /usr/local/bin/agent-browser
COPY --chmod=0755 vm-guest-agent /usr/local/bin/vm-guest-agent
COPY --chmod=0755 vm-init /sbin/vm-init
COPY --chmod=0755 browse /usr/local/bin/browse
COPY browser-smoke.cjs /tmp/browser-smoke.cjs
# Match the guest agent's cleared environment and identity, not Docker ENV defaults.
RUN setpriv --reuid=1000 --regid=1000 --clear-groups \
    env -i HOME=/home/jail PATH=/usr/local/bin:/usr/bin:/bin node /tmp/browser-smoke.cjs \
    && rm /tmp/browser-smoke.cjs \
    && rm -rf /home/jail/.agent-browser /home/jail/.agent-browser-profile
COPY toolkit-smoke.sh /tmp/toolkit-smoke.sh
RUN --network=none setpriv --reuid=1000 --regid=1000 --clear-groups \
    env -i HOME=/home/jail PATH=/usr/local/bin:/usr/bin:/bin sh /tmp/toolkit-smoke.sh \
    && rm /tmp/toolkit-smoke.sh
WORKDIR /home/jail
ENTRYPOINT ["/sbin/vm-init"]
