FROM golang:1.21-bullseye as builder

ARG VER=devel
ARG BUILDTAGS=""
ARG EXTERNAL="0"

ENV CGO_ENABLED=0

RUN mkdir -p /sshpiperd/plugins
WORKDIR /src
RUN --mount=target=/src,type=bind,source=. --mount=type=cache,target=/root/.cache/go-build if [ "$EXTERNAL" = "1" ]; then cp sshpiperd /sshpiperd; else go build -o /sshpiperd -ldflags "-X main.mainver=$VER" ./cmd/... ; fi
RUN --mount=target=/src,type=bind,source=. --mount=type=cache,target=/root/.cache/go-build if [ "$EXTERNAL" = "1" ]; then cp * /sshpiperd/plugins; rm /sshpiperd/plugins/Dockerfile; rm /sshpiperd/plugins/entrypoint.sh; rm /sshpiperd/plugins/sshpiperd ; else go build -o /sshpiperd/plugins -tags "$BUILDTAGS" ./plugin/...; fi
ADD entrypoint.sh /sshpiperd

FROM busybox
LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

COPY --from=ep76/openssh-static:latest /usr/bin/ssh-keygen /bin/ssh-keygen
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

CMD ["/sshpiperd/entrypoint.sh"]
