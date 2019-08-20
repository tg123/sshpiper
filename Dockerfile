FROM golang:1.12-alpine as builder

RUN apk update \
        && apk upgrade \
        && apk add --no-cache \
        ca-certificates \
        && update-ca-certificates 2>/dev/null
RUN apk add google-authenticator git gcc libc-dev linux-pam-dev

ADD . /go/src/github.com/tg123/sshpiper/
ENV GO111MODULE=on
WORKDIR /go/src/github.com/tg123/sshpiper/sshpiperd
RUN go build -ldflags "$(/go/src/github.com/tg123/sshpiper/sshpiperd/ldflags.sh)" -tags pam -o /go/bin/sshpiperd


FROM alpine:latest 
LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

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
