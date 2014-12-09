FROM golang:latest
MAINTAINER tgic <farmer1992@gmail.com>


RUN go get github.com/tg123/sshpiper/sshpiperd
RUN go install github.com/tg123/sshpiper/sshpiperd

EXPOSE 2222
CMD ["/go/bin/sshpiperd"]
