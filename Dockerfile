FROM golang:latest
MAINTAINER tgic <farmer1992@gmail.com>

RUN apt-get update && apt-get install -y libpam0g-dev libpam-google-authenticator

RUN go get -tags pam github.com/tg123/sshpiper/sshpiperd
RUN go install -tags pam github.com/tg123/sshpiper/sshpiperd

EXPOSE 2222

CMD ["sh", "-c", "/go/bin/sshpiperd -c=${CHALLENGER}"]
