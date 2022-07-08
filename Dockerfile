FROM golang:1.18-bullseye as builder

ARG VER=devel

ENV CGO_ENABLED=0

RUN mkdir -p /cache/crypto
COPY crypto /cache/crypto
COPY go.mod go.sum /cache/
WORKDIR /cache
RUN go mod download

RUN mkdir -p /sshpiperd/plugins
ADD . /src/
WORKDIR /src
RUN --mount=type=cache,target=/root/.cache/go-build go build -o /sshpiperd -ldflags "-X main.mainver=$VER" ./cmd/...
RUN --mount=type=cache,target=/root/.cache/go-build go build -o /sshpiperd/plugins  -ldflags "-X main.mainver=$VER" ./plugin/...
ADD entrypoint.sh /sshpiperd

FROM busybox
LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

COPY --from=ep76/openssh-static:latest /usr/bin/ssh-keygen /bin/ssh-keygen
RUN mkdir /etc/ssh/

COPY --from=builder /sshpiperd/ /sshpiperd
EXPOSE 2222

CMD ["/sshpiperd/entrypoint.sh"]
