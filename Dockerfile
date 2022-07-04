FROM golang:1.18-stretch as builder

ARG VER=devel

RUN mkdir -p /out
ADD . /src/
WORKDIR /src/cmd/sshpiperd
RUN CGO_ENABLED=0 go build -ldflags "-X main.mainver=$VER" -o /out/sshpiperd

WORKDIR /src/plugin/workingdir
RUN CGO_ENABLED=0 go build -o /out/workingdir

FROM busybox
LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

RUN mkdir /etc/ssh/

ADD entrypoint.sh /
COPY --from=builder /out/* /
COPY --from=ep76/openssh-static:latest /usr/bin/ssh-keygen /ssh-keygen
EXPOSE 2222

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/sshpiperd", "/workingdir"]
