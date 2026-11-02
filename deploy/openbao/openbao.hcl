# OpenBao server for Gatekeep key custody (AD-10), as the `openbao` Compose service in
# deploy/compose.yaml. Baked into the image by deploy/docker/openbao.Dockerfile.
#
# The container joins no network (network_mode: none). Hosts reach OpenBao only through
# the unix socket, on the openbao-socket volume. Raft refuses to start without a cluster
# address, and only a tcp listener supplies one, so a loopback tcp listener exists. With
# no network, that loopback is the container's own: nothing else can reach it.

ui = false

api_addr     = "unix:///run/openbao/openbao.sock"
cluster_addr = "https://127.0.0.1:8201"

storage "raft" {
  # The openbao-data volume. The Master Key is never on it.
  path    = "/var/lib/openbao/data"
  node_id = "gatekeep-1"
}

listener "unix" {
  address = "/run/openbao/openbao.sock"
  # OpenBao 2.7.2 ignores socket_mode and socket_group unless socket_user is set too.
  # Containers that need custody run with the gatekeep-custody group (gid 4500).
  socket_user  = "openbao"
  socket_group = "gatekeep-custody"
  socket_mode  = "0660"
}

# Loopback in the container's own network namespace only. Required by Raft.
listener "tcp" {
  address         = "127.0.0.1:8200"
  cluster_address = "127.0.0.1:8201"
  tls_disable     = true
}

# The Master Key: 32 random bytes made by the keygen service, handed to this container
# as the read-only Compose secret master_key. A missing file stops OpenBao starting. A
# weaker control than the retired TPM design: see docs/key-custody.md. Raise
# current_key_id on each seal rotation.
seal "static" {
  current_key_id = "gatekeep-master-1"
  current_key    = "file:///run/secrets/master_key"
}

# OpenBao 2.7.2 refuses to enable audit devices through the API, so it's declared here.
# The openbao-audit volume. Off-server shipping and decrypt-rate alerts read this file
# (later stories).
audit "file" "file" {
  description = "Every request, with secrets HMAC'd. Shipped off the server."
  options {
    file_path = "/var/log/openbao/audit.log"
    mode      = "0600"
  }
}
