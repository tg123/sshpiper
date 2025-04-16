FROM docker.io/golang:1.24-bookworm AS builder
ARG VER=devel
ARG BUILDTAGS
ARG EXTERNAL=0

ENV CGO_ENABLED=0
WORKDIR /src
RUN \
  --mount=target=/src,type=bind,source=. \
  --mount=type=cache,target=/root/.cache/go-build \
  <<HEREDOC
    if [ "${EXTERNAL}" = "1" ]; then
      cp sshpiperd /sshpiperd
      mkdir -p /sshpiperd/plugins
      cp -r plugins /sshpiperd
    else
      go build -o /sshpiperd -ldflags "-X main.mainver=${VER}" ./cmd/...
      go build -o /sshpiperd/plugins -tags "${BUILDTAGS}" ./plugin/... ./e2e/testplugin/...
    fi
HEREDOC


FROM builder AS testrunner
COPY --from=farmer1992/openssh-static:V_9_8_P1 /usr/bin/ssh /usr/bin/ssh-9.8p1
COPY --from=farmer1992/openssh-static:V_8_0_P1 /usr/bin/ssh /usr/bin/ssh-8.0p1


FROM docker.io/busybox AS sshpiperd
ARG USERID=1000
ARG GROUPID=1000
RUN <<HEREDOC
  # Add a non-root system (-S) user/group to run `sshpiperd` with:
  addgroup -g "${GROUPID}" -S sshpiperd
  adduser -u "${USERID}" -S sshpiperd -G sshpiperd

  # Support `SSHPIPERD_SERVER_KEY_GENERATE_MODE=notexist` to create host key at `/etc/ssh`:
  mkdir /etc/ssh/
  chown -R "${USERID}:${GROUPID}" /etc/ssh/
HEREDOC
COPY --from=builder --chown=${USERID} /sshpiperd/ /sshpiperd

# Runtime setup:
ENV SSHPIPERD_SERVER_KEY_GENERATE_MODE=notexist
ENTRYPOINT ["/sshpiperd/sshpiperd"]
CMD ["/sshpiperd/plugins/workingdir"]
EXPOSE 2222
USER ${USERID}:${GROUPID}
