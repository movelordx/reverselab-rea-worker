FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_VERSION=24.11.0 \
    GHIDRA_VERSION=12.1.4 \
    GHIDRA_DATE=20260921 \
    GHIDRA_SHA256=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db \
    PORT=10000

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip jq xz-utils openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) node_arch=x64 ;; arm64) node_arch=arm64 ;; *) echo "unsupported arch: $arch" && exit 1 ;; esac; \
    curl -fsSLo /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz"; \
    mkdir -p /opt/node; \
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1; \
    rm /tmp/node.tar.xz
ENV PATH="/opt/node/bin:${PATH}"

RUN npm install --global rea-agents@4.1.0

RUN curl -fsSLo /tmp/ghidra.zip \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && mkdir -p /opt/ghidra \
    && unzip -q /tmp/ghidra.zip -d /opt/ghidra \
    && rm /tmp/ghidra.zip

ENV GHIDRA_INSTALL_DIR="/opt/ghidra/ghidra_12.1.4_PUBLIC" \
    REA_ANALYSIS_PROVIDER=ghidra \
    NODE_ENV=production

RUN useradd --create-home --uid 10001 reverselab
WORKDIR /app
COPY package.json ./
COPY server.mjs ./server.mjs
RUN chown -R reverselab:reverselab /app /home/reverselab
USER reverselab

EXPOSE 10000
CMD ["node", "server.mjs"]
