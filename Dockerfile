FROM docker.io/node:24-bookworm-slim AS web-builder
WORKDIR /web
COPY cmd/sshpiperd-webadmin/internal/httpapi/web/package.json cmd/sshpiperd-webadmin/internal/httpapi/web/package-lock.json ./
RUN npm ci
COPY cmd/sshpiperd-webadmin/internal/httpapi/web/ ./
RUN npm run build


FROM docker.io/golang:1.26-bookworm AS builder
ARG VER=devel
ARG BUILDTAGS
ENV CGO_ENABLED=0
WORKDIR /src

# Single source of truth for the linux binaries shipped in the published
# images, in the GitHub release tarballs, and in the .snap files. The
# `make release` and `make snap` pipelines extract them from the
# `bin-export` stage below, so a single set of bytes flows through every
# release artifact. Compile flags (-trimpath, -s -w) match what the
# windows/darwin cross-compile step in `scripts/build-release.sh` applies.
RUN \
  --mount=target=/src,type=bind,source=. \
  --mount=from=web-builder,source=/web/dist,target=/src/cmd/sshpiperd-webadmin/internal/httpapi/web/dist \
  --mount=type=cache,target=/root/.cache/go-build \
  <<HEREDOC
    # Create directories required for `go build -o`:
    mkdir -p /sshpiperd/plugins

    go build -trimpath -ldflags "-s -w -X main.mainver=${VER}" \
      -o /sshpiperd ./cmd/...
    go build -trimpath -ldflags "-s -w" \
      -o /sshpiperd/plugins -tags "${BUILDTAGS}" \
      ./plugin/... ./e2e/testplugin/...
HEREDOC


FROM builder AS testrunner
COPY --from=farmer1992/openssh-static:V_9_8_P1 /usr/bin/ssh /usr/bin/ssh-9.8p1
COPY --from=farmer1992/openssh-static:V_8_0_P1 /usr/bin/ssh /usr/bin/ssh-8.0p1


# Binary-only stage used by `docker buildx build --target bin-export
# --output type=local,dest=…` so the host can extract the *exact* binaries
# that ship inside the runtime `sshpiperd` image. `make release-bins` and
# `make snap` both ingest these bytes, so the binaries packaged into the
# GH release archives and the .snap files are byte-identical to those in
# the published image.
FROM scratch AS bin-export
COPY --from=builder /sshpiperd/ /


FROM docker.io/busybox AS sshpiperd
ARG USERID=1000
ARG GROUPID=1000
RUN <<HEREDOC
  # Add a non-root system (-S) user/group to run `sshpiperd` with (final arg is group/user name):
  addgroup -S -g "${GROUPID}" sshpiperd 
  adduser  -S -u "${USERID}" -G sshpiperd sshpiperd

  # Support `SSHPIPERD_SERVER_KEY_GENERATE_MODE=notexist` to create host key at `/etc/ssh`:
  mkdir /etc/ssh/
  chown -R "${USERID}:${GROUPID}" /etc/ssh/
HEREDOC
COPY --from=builder --chown=${USERID} /sshpiperd/ /sshpiperd

# Runtime setup:
ENV SSHPIPERD_SERVER_KEY_GENERATE_MODE=notexist PLUGIN=workingdir
ENTRYPOINT ["/sshpiperd/sshpiperd"]

USER ${USERID}:${GROUPID}
EXPOSE 2222
