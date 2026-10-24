FROM node:18-bookworm-slim

# GenieACS is pure JS; pin a known-good 1.2.x release.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g genieacs@1.2.13 \
    && mkdir -p /opt/genieacs/ext

ENV GENIEACS_EXT_DIR=/opt/genieacs/ext

# cwmp, nbi, fs, ui
EXPOSE 7547 7557 7567 3000
