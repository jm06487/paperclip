# Paperclip OpenCode runtime image (MEC-200).
#
# Base is the upstream Paperclip agent runtime base, pinned by manifest digest.
# The base already provides Ubuntu 22.04, Node.js 24, git, tini, the
# paperclip-agent-shim, and the non-root `paperclip` user UID/GID 1000.
#
# This image adds only the OpenCode CLI at an exact npm version, installed from
# a committed lockfile so the tarball and integrity hash are pinned. It contains
# no API keys, tokens, OAuth files, kubeconfigs, or user home directories.
# Deployment is out of scope for this build.
#
# MEC-437 durable fix: the base is the CI-built, keyless-cosign-signed rebuild
# from the verified Go 1.27.3 shim tree (MEC-485). It carries refreshed Ubuntu
# 22.04 packages and clears the four shim CVEs and CVE-2026-84782, so this image
# needs no Trivy exception file. OpenSSL stays explicitly upgraded and floored.
#
# The pin is immutable. A new base digest needs a new reviewed change.

ARG BASE_IMAGE=harbor.edge.mechagora.net/paperclip-opencode/agent-runtime-base@sha256:e0ea0000ef401a7504f4b85cfadd1e2e9b312102b21c3473d1bec07eea44f3e5
FROM ${BASE_IMAGE}

USER root
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG OPENCODE_VERSION=1.19.3

# MEC-435 condition 2: the base ships an OpenSSL affected by CVE-2026-... fixes
# released as 3.0.2-0ubuntu1.30. Upgrade both packages and fail the build if the
# installed version is older than the approved minimum.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libssl3 openssl \
    && test "$(dpkg-query -W -f='${Version}' libssl3)" != "" \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libssl3)" ge 3.0.2-0ubuntu1.30 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' openssl)" ge 3.0.2-0ubuntu1.30 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/opencode-runtime
COPY package.json package-lock.json ./

RUN npm ci --no-audit --no-fund \
    && ln -s /opt/opencode-runtime/node_modules/.bin/opencode /usr/local/bin/opencode \
    && test "$(node -p "require('./node_modules/opencode-ai/package.json').version")" = "${OPENCODE_VERSION}" \
    && chown -R 1000:1000 /opt/opencode-runtime

# MEC-435 condition 3: remove npm (and npx) from the final image after `npm ci`.
# Node.js and the installed OpenCode CLI stay. Do not replace npm with a newer
# global npm: http-cache-semantics 4.2.0 has no fixed version.
RUN npm_prefix="$(npm prefix -g)" \
    && npm_root="$(npm root -g)" \
    && rm -rf "${npm_root}/npm" "${npm_root}/corepack" \
    && for bin in npm npx corepack; do \
         for path in "${npm_prefix}/bin/${bin}" "$(command -v "${bin}" 2>/dev/null || true)"; do \
           if [ -n "${path}" ] && [ -e "${path}" ]; then rm -f "${path}"; fi; \
         done; \
       done \
    && rm -rf /root/.npm \
    && ! command -v npm \
    && ! command -v npx \
    && command -v node >/dev/null 2>&1

# Restore the reviewed non-root runtime identity. The CLI must be on PATH for
# the Paperclip agent shim, which resolves the command with exec.LookPath.
USER 1000:1000
ENV HOME=/home/paperclip

RUN test "$(id -u)" = "1000" \
    && command -v node >/dev/null 2>&1 \
    && ! command -v npm \
    && ! command -v npx \
    && command -v opencode >/dev/null 2>&1 \
    && opencode --version | grep -F "${OPENCODE_VERSION}" >/dev/null

LABEL org.opencontainers.image.title="Paperclip OpenCode agent runtime" \
      org.opencontainers.image.description="Non-root Paperclip agent runtime with the pinned OpenCode CLI" \
      org.opencontainers.image.base.name="harbor.edge.mechagora.net/paperclip-opencode/agent-runtime-base@sha256:e0ea0000ef401a7504f4b85cfadd1e2e9b312102b21c3473d1bec07eea44f3e5" \
      org.mechagora.paperclip.runtime="opencode" \
      org.mechagora.paperclip.opencode.version="${OPENCODE_VERSION}" \
      org.mechagora.paperclip.publication="CI only; never hand-built" \
      org.mechagora.paperclip.harbor.repository="harbor.edge.mechagora.net/paperclip-opencode/agent-runtime-opencode" \
      org.mechagora.paperclip.runtime.base.ruling="MEC-437" \
      org.mechagora.paperclip.runtime.base.build="MEC-485"

WORKDIR /workspace
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/paperclip-agent-shim"]
