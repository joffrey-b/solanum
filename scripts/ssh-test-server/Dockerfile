# Throwaway sshd servers for the live SSH tests (src-tauri/src/ssh_stack_tests.rs).
# Never publish or reuse this image: it has a known password and generated-at-build host keys.
FROM debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server tcsh fish && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash tester && echo 'tester:pw' | chpasswd
# Login shells that are not POSIX sh, for the remote-script tests (remote_exec.rs).
RUN useradd -m -s /usr/bin/tcsh cshuser && echo 'cshuser:pw' | chpasswd && \
    useradd -m -s /usr/bin/fish fishuser && echo 'fishuser:pw' | chpasswd
RUN mkdir -p /home/tester/.ssh /etc/ssh/keys && \
    ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/keys/ed25519 && \
    ssh-keygen -q -t rsa -b 3072 -N '' -f /etc/ssh/keys/rsa && \
    ssh-keygen -q -t ecdsa -b 256 -N '' -f /etc/ssh/keys/ecdsa
# For the atomic-replace tests (atomic_transfer.rs): a root-owned file the test
# user may write but not take over, and a folder it cannot write holding a file
# it owns (both must be written in place, keeping owner and folder as they
# are), and a file in a group the user belongs to but not as its primary group
# (the replacement must keep that group).
RUN usermod -aG staff tester && \
    install -d -o tester -g tester -m 755 /srv/solanum && \
    install -o root -g root -m 666 /dev/null /srv/solanum/root-owned.txt && \
    install -d -o root -g root -m 755 /srv/solanum/locked && \
    install -o tester -g tester -m 644 /dev/null /srv/solanum/locked/mine.txt && \
    install -d -o tester -g tester -m 755 /srv/solanum/team && \
    install -o tester -g staff -m 664 /dev/null /srv/solanum/team/team.txt
COPY authorized_keys /home/tester/.ssh/authorized_keys
RUN chown -R tester:tester /home/tester/.ssh && chmod 700 /home/tester/.ssh && chmod 600 /home/tester/.ssh/authorized_keys
COPY sshd_common.conf sshd_modern.conf sshd_legacy14.conf sshd_legacy1.conf sshd_noforward.conf sshd_keypassword.conf sshd_keykbi.conf sshd_sha1hostkey.conf sshd_gatewayports.conf sshd_onesession.conf sshd_ecdhkex.conf sshd_internal.conf /etc/ssh/
COPY start.sh /start.sh
CMD ["/start.sh"]
