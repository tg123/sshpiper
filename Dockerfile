FROM docker.io/golang:1.22-bullseye as builder

ARG VER=devel
ARG BUILDTAGS=""
ARG EXTERNAL="0"

ENV CGO_ENABLED=0

RUN mkdir -p /sshpiperd/plugins
WORKDIR /src
RUN --mount=target=/src,type=bind,source=. --mount=type=cache,target=/root/.cache/go-build if [ "$EXTERNAL" = "1" ]; then cp sshpiperd /sshpiperd; else go build -o /sshpiperd -ldflags "-X main.mainver=$VER" ./cmd/... ; fi
RUN --mount=target=/src,type=bind,source=. --mount=type=cache,target=/root/.cache/go-build if [ "$EXTERNAL" = "1" ]; then cp -r plugins /sshpiperd ; else go build -o /sshpiperd/plugins -tags "$BUILDTAGS" ./plugin/...; fi
ADD entrypoint.sh /sshpiperd

FROM docker.io/busybox
LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

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

ENTRYPOINT ["/sshpiperd/entrypoint.sh"]
