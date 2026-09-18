# syntax=docker/dockerfile:1
#
# Vaultonaut headless container — for the roles that never mount a drive: a relay hub, a serving node, or a headless
# automation run. Mounting a vault as an ordinary drive is a desktop feature and is intentionally NOT a container
# role: a mount needs kernel FUSE, is invisible to a macOS or Windows host (the container runs in a Linux VM there),
# and would require privileges that defeat the point of a container. The desktop app remains the way to mount.
#
# A serving node serves only the ENCRYPTED files; the vault password and contents never enter the container. A relay
# carries no vault data at all. So even a fully compromised container leaks no plaintext and no master key.

# ---- builder: install production dependencies only ----
FROM node:24.11.1-bookworm-slim AS builder
WORKDIR /app
# Copy only the manifest first so the dependency layer stays cached when only source changes. This project does not
# commit a lockfile (dependency versions resolve from the ranges in package.json), so install from package.json alone.
COPY package.json ./
# A production-only install. --ignore-scripts blocks any dependency lifecycle script from running at build time (all
# of this project's runtime dependencies are plain JavaScript or WebAssembly, so none is needed).
RUN npm install --omit=dev --ignore-scripts

# ---- runtime: minimal and non-root ----
# Pinned to the exact Node the project ships and tests with (engines.node is >=24.7.0; the desktop bundle and CI pin
# 24.11.1). The self-check's post-quantum signature verification needs Node 24.7 or newer, so the runtime must match.
# For an even smaller, shell-less image you can switch this stage to a minimal non-root base after build-testing; the
# entrypoint and health probe are plain Node on purpose so they run either way.
FROM node:24.11.1-bookworm-slim AS runtime
LABEL org.opencontainers.image.title="Vaultonaut" \
      org.opencontainers.image.description="Headless relay and serving nodes for encrypted vaults" \
      org.opencontainers.image.licenses="AGPL-3.0"

# XDG_DATA_HOME puts the persistent data directory (vault stores, the checksum-verified engine cache, and node state)
# at a fixed path a volume can cover. NODE_ENV=production is the standard production signal.
ENV NODE_ENV=production \
    XDG_DATA_HOME=/data
WORKDIR /app

# The production dependency tree from the builder stage. --chown assigns ownership as the files are copied, so there
# is no later `chown -R` that would rewrite every file into a second, duplicate image layer.
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
# The application plus the signed release manifest and the two documentation files the self-check verifies. Copying an
# explicit set (not the whole tree) keeps the image small and guarantees the signed set is present and unmodified, so
# `verify-self` verifies on every start.
COPY --chown=node:node package.json vaultonaut.js verify.js CONTRIBUTING.md LICENSE ./
COPY --chown=node:node lib ./lib
COPY --chown=node:node release-manifest.json release-manifest.sig release-manifest.sig.pq ./
COPY --chown=node:node docs/README.md docs/banner.png ./docs/
COPY --chown=node:node docker/entrypoint.js docker/healthcheck.js ./docker/

# A writable, persistent data directory owned by the non-root user, so a freshly mounted volume is writable. The
# `node` user (uid 1000) already exists in the official base image. Only /data needs chowning; the app files were
# copied with the right ownership above.
RUN mkdir -p /data && chown node:node /data
USER node

# Report healthy only once the node's port is accepting connections. Each role sets HEALTHCHECK_PORT in the compose
# file (a relay's control port, or a serving node's serve port).
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD ["node", "/app/docker/healthcheck.js"]

# Self-attest (verify the signed bundle), then run the requested Vaultonaut command. Override CMD to pick a role, for
# example: relay --token-file /run/secrets/relay_token --host <public-host>:7443
ENTRYPOINT ["node", "/app/docker/entrypoint.js"]
CMD ["help"]
