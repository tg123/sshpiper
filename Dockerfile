FROM golang:1.18-stretch as builder

ARG VER=devel

RUN mkdir -p /out/plugins
ADD . /src/
WORKDIR /src
RUN CGO_ENABLED=0 go build -o /out -ldflags "-X main.mainver=$VER" ./cmd/...
RUN CGO_ENABLED=0 go build -o /out/plugins  -ldflags "-X main.mainver=$VER" ./plugin/...

FROM busybox
LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

RUN mkdir /etc/ssh/

ADD entrypoint.sh /
COPY --from=builder /out/ /
COPY --from=ep76/openssh-static:latest /usr/bin/ssh-keygen /ssh-keygen
EXPOSE 2222

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/sshpiperd", "/plugins/workingdir"]
