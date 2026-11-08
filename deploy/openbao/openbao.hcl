# OpenBao server for Gatekeep key custody (AD-10), as the `openbao` Compose service in
# deploy/compose.yaml. Baked into the image by deploy/docker/openbao.Dockerfile.
#
# A template: deploy/openbao/start-openbao.sh renders it onto a tmpfs at each start, filling
# in the Master Key's ID and, in rotation mode only, the previous generation (Story 12.7).
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
  # No root token can be generated without one. start-openbao.sh turns this to false on this
  # listener in rotation mode only (deploy/compose.rotate.yaml), for the root-key step.
  disable_unauthed_generate_root_endpoints = true
}

# Loopback in the container's own network namespace only. Required by Raft.
listener "tcp" {
  address         = "127.0.0.1:8200"
  cluster_address = "127.0.0.1:8201"
  tls_disable     = true
  disable_unauthed_generate_root_endpoints = true
}

# The Master Key: 32 random bytes made by the keygen service, handed to this container
# as the read-only Compose secret master_key. A missing file stops OpenBao starting. A
# weaker control than the retired TPM design: see docs/key-custody.md. The key ID is
# rendered from the master_key_id secret, gatekeep-master-<N> for generation N, and rotation
# mode adds previous_key_id and previous_key after current_key.
seal "static" {
  current_key_id = "@MASTER_KEY_ID@"
  current_key    = "file:///run/secrets/master_key"
}

# OpenBao 2.7.2 refuses to enable audit devices through the API, so it's declared here.
# The openbao-audit volume. The openbao-audit-shipper service copies what is appended into
# the Object Lock bucket (Story 1.30), reading it through the openbao-audit group, which
# start-openbao.sh gives the file and its directory, so the mode lets that group read and
# nobody else. Decrypt-rate alerts will read it too (Story 11.2).
#
# The device keeps its default HMAC of every request and response value: no log_raw, and
# neither hmac_accessor nor elide_list_responses is turned off. A test fails if one appears.
audit "file" "file" {
  description = "Every request, with secrets HMAC'd. Shipped off the server."
  options {
    file_path = "/var/log/openbao/audit.log"
    mode      = "0640"
  }
}
