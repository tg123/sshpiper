FROM golang:1.18-stretch as builder

ARG VER=devel

ADD . /src/
WORKDIR /src/sshpiperd
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=$VER" -o /sshpiperd


FROM busybox
LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

RUN mkdir /etc/ssh/

ADD entrypoint.sh /
COPY --from=builder /sshpiperd /
EXPOSE 2222

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/sshpiperd", "daemon"]
