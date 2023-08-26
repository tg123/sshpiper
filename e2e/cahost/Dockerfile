FROM debian:bookworm-slim

EXPOSE 2222

ENV DEBIAN_FRONTEND=noninteractive

COPY ca.pub /etc/ssh/trusted-ca.pub

RUN apt -y update \
    && apt -y install --no-install-recommends --no-install-suggests openssh-server \
    && mkdir -p /run/sshd \
    && adduser --disabled-password --gecos "" client_123 \
    && passwd -d client_123 \
    && rm -rf /var/lib/apt/lists/*

COPY sshd_config /etc/ssh/sshd_config

ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"]

