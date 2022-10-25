FROM golang:1.19-bullseye as builder

ARG VER=devel
ARG BUILDTAGS=""

ENV CGO_ENABLED=0

RUN mkdir -p /sshpiperd/plugins
WORKDIR /src
RUN --mount=target=/src,type=bind,source=. --mount=type=cache,target=/root/.cache/go-build go build -o /sshpiperd -ldflags "-X main.mainver=$VER" ./cmd/...
RUN --mount=target=/src,type=bind,source=. --mount=type=cache,target=/root/.cache/go-build go build -o /sshpiperd/plugins -tags "$BUILDTAGS" ./plugin/...
ADD entrypoint.sh /sshpiperd

FROM busybox
LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

COPY --from=ep76/openssh-static:latest /usr/bin/ssh-keygen /bin/ssh-keygen
RUN mkdir /etc/ssh/

COPY --from=builder /sshpiperd/ /sshpiperd
EXPOSE 2222

CMD ["/sshpiperd/entrypoint.sh"]
