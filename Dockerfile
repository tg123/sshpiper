FROM docker.io/golang:1.24-bookworm as builder

ARG VER=devel
ARG BUILDTAGS
ARG EXTERNAL=0

ENV CGO_ENABLED=0

WORKDIR /src
RUN \
  --mount=target=/src,type=bind,source=. \
  --mount=type=cache,target=/root/.cache/go-build \
  <<HEREDOC
    # Create directories required for `cp` / `go build -o`:
    mkdir -p /sshpiperd/plugins

    if [ "${EXTERNAL}" = "1" ]; then
      cp sshpiperd /sshpiperd
      cp -r plugins /sshpiperd
    else
      go build -o /sshpiperd -ldflags "-X main.mainver=${VER}" ./cmd/...
      go build -o /sshpiperd/plugins -tags "${BUILDTAGS}" ./plugin/... ./e2e/testplugin/...
    fi
HEREDOC
ADD entrypoint.sh /sshpiperd

FROM builder as testrunner
COPY --from=farmer1992/openssh-static:V_9_8_P1 /usr/bin/ssh /usr/bin/ssh-9.8p1
COPY --from=farmer1992/openssh-static:V_8_0_P1 /usr/bin/ssh /usr/bin/ssh-8.0p1

FROM docker.io/busybox
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
USER ${USERID}:${GROUPID}
EXPOSE 2222

ENTRYPOINT ["/sshpiperd/entrypoint.sh"]
