FROM golang:latest as builder

RUN apt-get update && apt-get install -y libpam0g-dev

ADD . /go/src/github.com/tg123/sshpiper/
RUN go install -ldflags "$(/go/src/github.com/tg123/sshpiper/sshpiperd/ldflags.sh)" -tags pam github.com/tg123/sshpiper/sshpiperd


FROM alpine:latest 
LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
RUN apk update \
        && apk upgrade \
        && apk add --no-cache \
        ca-certificates \
        && update-ca-certificates 2>/dev/null
        
RUN apk add google-authenticator

RUN mkdir /etc/ssh/

ADD entrypoint.sh /
COPY --from=builder /go/bin/sshpiperd /
EXPOSE 2222

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/sshpiperd", "daemon"]
