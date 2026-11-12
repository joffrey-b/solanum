#!/usr/bin/env bash
# Runs the ignored `live_*` SSH tests against throwaway sshd containers bound to 127.0.0.1.
# Needs Docker, ssh-keygen and a Rust toolchain. Extra arguments go to the test binary.
#   :2201 modern sshd            :2202 legacy: DH-group14-SHA1, ssh-rsa, HMAC-SHA1, AES-CTR
#   :2203 legacy: DH-group1-SHA1  :2204 sshd with AllowTcpForwarding no
#   :2205 AuthenticationMethods publickey,password
#   :2206 AuthenticationMethods publickey,keyboard-interactive
#   :2207 modern key exchange, but only ssh-rsa (SHA-1) host-key signatures
#   :2208 GatewayPorts clientspecified (the client picks the remote-forward bind address)
#   :2209 MaxSessions 1 (one channel per connection)
#   :2210 the key exchanges Cisco IOS offers: ECDH on the NIST curves and DH-group14-SHA1
#   :2299 inside the container only (not published): reachable through a jump host, never directly
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
name=solanum-sshtest
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

mkdir -p "$work/keys" "$work/out" "$work/image"
(
  cd "$work/keys"
  ssh-keygen -q -t ed25519 -N '' -C t-ed -f ed25519
  ssh-keygen -q -t ed25519 -N 'secret-pass' -C t-edp -f ed25519_pass
  ssh-keygen -q -t rsa -b 3072 -N '' -C t-rsa -f rsa
  ssh-keygen -q -t rsa -b 3072 -N '' -m PEM -C t-rsapem -f rsa_pem
  ssh-keygen -q -t ecdsa -b 256 -N '' -C t-ec -f ecdsa
  ssh-keygen -q -t ecdsa -b 256 -N '' -m PEM -C t-ecpem -f ecdsa_pem
)
# PuTTY .ppk fixtures: bundled test vectors from the `ssh-key` crate itself
# (converted by real puttygen, per its own tests/private_key.rs), not
# something we generate — there's no writer for this format available here.
# Encrypted variants all share the crate's documented test passphrase "123".
ssh_key_examples="$(find "$HOME/.cargo/registry/src" -maxdepth 2 -type d -name 'ssh-key-*' | head -1)/tests/examples"
cp "$ssh_key_examples"/id_ed25519.ppk "$ssh_key_examples"/id_ed25519.pub \
   "$ssh_key_examples"/id_ed25519_enc.ppk \
   "$ssh_key_examples"/id_rsa_3072.ppk "$ssh_key_examples"/id_rsa_3072.pub \
   "$ssh_key_examples"/id_rsa_3072_enc.ppk \
   "$work/keys/"
cp "$here"/Dockerfile "$here"/start.sh "$here"/sshd_*.conf "$work/image/"
cat "$work"/keys/*.pub > "$work/image/authorized_keys"

docker build -q -t "$name" "$work/image" >/dev/null
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" \
  -p 127.0.0.1:2201:2201 -p 127.0.0.1:2202:2202 -p 127.0.0.1:2203:2203 -p 127.0.0.1:2204:2204 \
  -p 127.0.0.1:2205:2205 -p 127.0.0.1:2206:2206 -p 127.0.0.1:2207:2207 -p 127.0.0.1:2208:2208 \
  -p 127.0.0.1:2209:2209 -p 127.0.0.1:2210:2210 \
  "$name" >/dev/null

for _ in $(seq 1 30); do
  if docker exec "$name" test -s /tmp/hostkeys.txt 2>/dev/null && (exec 3<>/dev/tcp/127.0.0.1/2210) 2>/dev/null; then break; fi
  sleep 1
done
docker exec "$name" cat /tmp/hostkeys.txt > "$work/out/hostkeys.txt"

cd "$repo/src-tauri"
[ -f ../dist/index.html ] || { mkdir -p ../dist; echo '<!doctype html><title>ci</title>' > ../dist/index.html; }
SOLANUM_SSH_FIXTURES="$work" cargo test --locked --lib ssh_stack_tests -- --ignored --test-threads=1 "$@"
