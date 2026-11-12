#!/bin/sh
# Starts the throwaway sshd instances and records the host-key fingerprints for the tests.
mkdir -p /run/sshd
for c in modern legacy14 legacy1 noforward keypassword keykbi sha1hostkey gatewayports onesession ecdhkex internal; do /usr/sbin/sshd -f /etc/ssh/sshd_$c.conf -E /var/log/sshd_$c.log; done
{
  ssh-keygen -lf /etc/ssh/keys/ed25519.pub
  ssh-keygen -lf /etc/ssh/keys/rsa.pub
  ssh-keygen -lf /etc/ssh/keys/ecdsa.pub
} > /tmp/hostkeys.txt
exec tail -F /var/log/sshd_modern.log /var/log/sshd_legacy14.log /var/log/sshd_legacy1.log /var/log/sshd_noforward.log /var/log/sshd_keypassword.log /var/log/sshd_keykbi.log /var/log/sshd_sha1hostkey.log /var/log/sshd_gatewayports.log /var/log/sshd_onesession.log /var/log/sshd_ecdhkex.log /var/log/sshd_internal.log
