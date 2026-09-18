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
RUN npm install --omit=dev --ignore-scripts --no-audit --no-fund

# Bake the storage engine at build time, so a serving node has it already present and NEVER downloads anything on its
# first serve — an air-gapped or egress-restricted node works, and there is no runtime network dependency. The bake
# reuses the app's own RcloneSetup, which is the single source of the pinned engine version and its committed
# checksums, so nothing here names a version and there is no drift; the engine and its license land in /engine, which
# the runtime stage copies in. A fetch or checksum failure fails the build, so a bad engine can never ship. Note this
# is the one step that needs network access, and only at BUILD time (to fetch the pinned engine); the resulting image
# has no runtime network dependency for the engine. To build fully offline, pre-place the pinned engine and license in
# /engine and this bake becomes a no-op — see docker/bake-engine.js.
COPY lib ./lib
COPY docker/bake-engine.js ./docker/bake-engine.js
RUN VAULTONAUT_ENGINE_DIR=/engine node docker/bake-engine.js

# ---- runtime: minimal and non-root ----
# Pinned to the exact Node the project ships and tests with (engines.node is >=24.7.0; the desktop bundle and CI pin
# 24.11.1). The self-check's post-quantum signature verification needs Node 24.7 or newer, so the runtime must match.
# For an even smaller, shell-less image you can switch this stage to a minimal non-root base after build-testing; the
# entrypoint and health probe are plain Node on purpose so they run either way.
FROM node:24.11.1-bookworm-slim AS runtime
LABEL org.opencontainers.image.title="Vaultonaut" \
      org.opencontainers.image.description="Headless relay and serving nodes for encrypted vaults" \
      org.opencontainers.image.licenses="AGPL-3.0"

# XDG_DATA_HOME puts the persistent data directory (vault stores and node state) at a fixed path a volume can cover.
# VAULTONAUT_ENGINE_DIR points the app at the engine baked into the image at /engine (outside the data volume, so a
# fresh volume never shadows it), so a serving node uses the already-verified engine and needs no download. HOME
# points at the writable data volume too, so any stray write to the home directory (by the engine or Node) lands on
# the volume rather than failing against the read-only root filesystem. NODE_ENV is the standard production signal.
ENV NODE_ENV=production \
    XDG_DATA_HOME=/data \
    VAULTONAUT_ENGINE_DIR=/engine \
    HOME=/data
WORKDIR /app

# The production dependency tree from the builder stage. --chown assigns ownership as the files are copied, so there
# is no later `chown -R` that would rewrite every file into a second, duplicate image layer.
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
# The application plus the signed release manifest and the two documentation files the self-check verifies. Copying an
# explicit set (not the whole tree) keeps the image small and guarantees the signed set is present and unmodified, so
# `verify-self` verifies on every start.
COPY --chown=node:node package.json vaultonaut.js verify.js CONTRIBUTING.md LICENSE ./
COPY --chown=node:node lib ./lib
# Hard guarantee that the self-check sees only the signed set: prune the two directories that are not part of the
# signed release manifest and are never loaded at runtime. The root .dockerignore normally keeps them out of the build
# context entirely, so this is usually a no-op — but running it here means a build under the legacy builder (or any
# context that bypasses the ignore file) still cannot ship them and trip the boot-time verify-self into TAMPERED.
RUN rm -rf ./lib/test ./lib/scripts
COPY --chown=node:node release-manifest.json release-manifest.sig release-manifest.sig.pq ./
COPY --chown=node:node docs/README.md docs/banner.png ./docs/
COPY --chown=node:node docker/entrypoint.js docker/healthcheck.js ./docker/
# The engine baked and checksum-verified in the builder stage, plus its license, owned by the runtime user. It lives
# outside /data so a mounted data volume never hides it, and the read-only root filesystem is fine because the app
# only reads and runs it (never re-downloads it, since it is already the pinned, verified build).
COPY --chown=node:node --from=builder /engine /engine

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
