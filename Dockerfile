ARG EXTERNAL=0

FROM docker.io/rust:1-alpine AS rust-builder
ARG VER=devel
RUN apk add --no-cache build-base protobuf
ENV PROTOC=/usr/bin/protoc
WORKDIR /src
COPY rust/ rust/
COPY libplugin/plugin.proto libplugin/plugin.proto
COPY libplugin/connovergrpc/connovergrpc.proto libplugin/connovergrpc/connovergrpc.proto
COPY libadmin/admin.proto libadmin/admin.proto
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/rust/target \
    SSHPIPERD_VERSION="${VER}" cargo build --locked --release --manifest-path rust/Cargo.toml --bin sshpiperd && \
    mkdir /out && cp rust/target/release/sshpiperd /out/sshpiperd

FROM docker.io/node:24-bookworm-slim AS web-builder
WORKDIR /web
COPY cmd/sshpiperd-webadmin/internal/httpapi/web/package.json cmd/sshpiperd-webadmin/internal/httpapi/web/package-lock.json ./
RUN npm ci
COPY cmd/sshpiperd-webadmin/internal/httpapi/web/ ./
RUN npm run build


FROM docker.io/golang:1.27-bookworm AS build-0
ARG VER=devel
ARG BUILDTAGS
ENV CGO_ENABLED=0
WORKDIR /src

RUN \
  --mount=target=/src,type=bind,source=. \
  --mount=from=web-builder,source=/web/dist,target=/src/cmd/sshpiperd-webadmin/internal/httpapi/web/dist \
  --mount=type=cache,target=/root/.cache/go-build \
  <<HEREDOC
    # Create directories required for `cp` / `go build -o`:
    mkdir -p /sshpiperd/plugins

    go build -o /sshpiperd/sshpiperd-admin -ldflags "-X main.mainver=${VER}" ./cmd/sshpiperd-admin
    go build -o /sshpiperd/sshpiperd-webadmin -ldflags "-X main.mainver=${VER}" ./cmd/sshpiperd-webadmin
    go build -o /sshpiperd/plugins -tags "${BUILDTAGS}" ./plugin/... ./e2e/testplugin/...
HEREDOC
COPY --from=rust-builder /out/sshpiperd /sshpiperd/sshpiperd

FROM docker.io/busybox AS build-1
ARG TARGETARCH
WORKDIR /prebuilt
COPY . .
RUN <<HEREDOC
    set -eu
    mkdir -p /sshpiperd
    cp "native/linux_${TARGETARCH}/sshpiperd" /sshpiperd/sshpiperd
    chmod 755 /sshpiperd/sshpiperd
    cp -r plugins /sshpiperd/
    for binary in sshpiperd-webadmin sshpiperd-admin; do
      if [ -f "$binary" ]; then cp "$binary" /sshpiperd/; fi
    done
HEREDOC

FROM build-${EXTERNAL} AS selected-daemon

FROM selected-daemon AS testrunner
COPY --from=farmer1992/openssh-static:V_9_8_P1 /usr/bin/ssh /usr/bin/ssh-9.8p1
COPY --from=farmer1992/openssh-static:V_8_0_P1 /usr/bin/ssh /usr/bin/ssh-8.0p1

FROM docker.io/alpine:3 AS init
RUN apk add --no-cache tini-static

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
COPY --from=selected-daemon --chown=${USERID} /sshpiperd/ /sshpiperd
COPY --from=init /sbin/tini-static /sbin/tini

# Runtime setup:
ENV SSHPIPERD_SERVER_KEY_GENERATE_MODE=notexist PLUGIN=workingdir
ENTRYPOINT ["/sbin/tini", "--", "/sshpiperd/sshpiperd"]

USER ${USERID}:${GROUPID}
EXPOSE 2222
