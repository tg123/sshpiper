# syntax=docker.io/docker/dockerfile-upstream:1.14.0
FROM scratch AS tini
ARG TARGETARCH
ADD --chmod=+x https://github.com/krallin/tini/releases/download/v0.19.0/tini-${TARGETARCH} /tini

FROM docker.io/golang:1.24-bookworm AS builder

ARG VER=devel
ARG BUILDTAGS=""
ARG EXTERNAL="0"

ENV CGO_ENABLED=0

RUN mkdir -p /sshpiperd/plugins
WORKDIR /src
RUN --mount=target=/src,type=bind,source=. --mount=type=cache,target=/root/.cache/go-build if [ "$EXTERNAL" = "1" ]; then cp sshpiperd /sshpiperd; else go build -o /sshpiperd -ldflags "-X main.mainver=$VER" ./cmd/... ; fi
RUN --mount=target=/src,type=bind,source=. --mount=type=cache,target=/root/.cache/go-build if [ "$EXTERNAL" = "1" ]; then cp -r plugins /sshpiperd ; else go build -o /sshpiperd/plugins -tags "$BUILDTAGS" ./plugin/... ./e2e/testplugin/...; fi
ADD entrypoint.sh /sshpiperd

FROM builder AS testrunner

COPY --from=farmer1992/openssh-static:V_9_8_P1 /usr/bin/ssh /usr/bin/ssh-9.8p1
COPY --from=farmer1992/openssh-static:V_8_0_P1 /usr/bin/ssh /usr/bin/ssh-8.0p1

FROM docker.io/busybox AS sshpiperd
# LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

RUN mkdir /etc/ssh/

# Add user nobody with id 1
ARG USERID=1000
ARG GROUPID=1000
RUN addgroup -g $GROUPID -S sshpiperd && adduser -u $USERID -S sshpiperd -G sshpiperd

# Add execution rwx to user 1
RUN chown -R $USERID:$GROUPID /etc/ssh/

USER $USERID:$GROUPID

COPY --from=builder --chown=$USERID /sshpiperd/ /sshpiperd
EXPOSE 2222

COPY --link --from=tini /tini /tini
ENTRYPOINT ["/tini", "--", "/sshpiperd/entrypoint.sh"]
