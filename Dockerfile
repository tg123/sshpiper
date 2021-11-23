FROM golang:1.17-alpine as builder

RUN apk update \
        && apk upgrade \
        && apk add --no-cache \
        ca-certificates git \
        && update-ca-certificates 2>/dev/null

ADD . /go/src/github.com/tg123/sshpiper/
WORKDIR /go/src/github.com/tg123/sshpiper/sshpiperd
RUN CGO_ENABLED=0 go build -ldflags "$(/go/src/github.com/tg123/sshpiper/sshpiperd/ldflags.sh)" -o /go/bin/sshpiperd


FROM alpine:latest 
LABEL maintainer="Boshi Lian<farmer1992@gmail.com>"

RUN apk update \
        && apk upgrade \
        && apk add --no-cache \
        ca-certificates \
        && update-ca-certificates 2>/dev/null
        
RUN mkdir /etc/ssh/

ADD entrypoint.sh /
COPY --from=builder /go/bin/sshpiperd /
EXPOSE 2222

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/sshpiperd", "daemon"]
