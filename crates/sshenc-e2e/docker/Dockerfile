FROM alpine:3.20

RUN apk add --no-cache openssh-server bash ca-certificates \
    && adduser -D -s /bin/bash sshtest \
    && passwd -u sshtest \
    && mkdir -p /home/sshtest/.ssh \
    && chmod 700 /home/sshtest/.ssh \
    && chown -R sshtest:sshtest /home/sshtest/.ssh

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
