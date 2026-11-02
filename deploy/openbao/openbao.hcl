# OpenBao server for Gatekeep key custody (AD-10). Run by openbao.service, never by hand.
# Verified on OpenBao 2.7.2 in a container (Story 1.7). Not yet run under systemd: see G-10.
#
# Hosts reach OpenBao only through the unix socket. Raft refuses to start without a
# cluster address, and only a tcp listener supplies one, so a loopback tcp listener
# exists. openbao.service runs OpenBao with PrivateNetwork=yes, so that loopback is
# OpenBao's own network namespace: no other process on the host can reach it.

ui = false

api_addr     = "unix:///run/openbao/openbao.sock"
cluster_addr = "https://127.0.0.1:8201"

storage "raft" {
  # On the OpenBao LUKS volume. openbao.service won't start unless it's mounted.
  path    = "/var/lib/openbao/data"
  node_id = "gatekeep-1"
}

listener "unix" {
  address = "/run/openbao/openbao.sock"
  # OpenBao 2.7.2 ignores socket_mode and socket_group unless socket_user is set too.
  socket_user  = "openbao"
  socket_group = "gatekeep-custody"
  socket_mode  = "0660"
}

# Loopback inside PrivateNetwork=yes only. Required by Raft for its cluster address.
listener "tcp" {
  address         = "127.0.0.1:8200"
  cluster_address = "127.0.0.1:8201"
  tls_disable     = true
}

# The Master Key: 32 random bytes that systemd's LoadCredential= copies from the
# root-only file on the key volume into this service's credential directory, which
# is $CREDENTIALS_DIRECTORY for openbao.service. A weaker control than the TPM design:
# see docs/spikes/1-2-key-custody.md. Raise current_key_id on each seal rotation.
seal "static" {
  current_key_id = "gatekeep-master-1"
  current_key    = "file:///run/credentials/openbao.service/master-key"
}

# OpenBao 2.7.2 refuses to enable audit devices through the API, so it's declared here.
# Off-server shipping and decrypt-rate alerts read this file (later stories).
audit "file" "file" {
  description = "Every request, with secrets HMAC'd. Shipped off the server."
  options {
    file_path = "/var/log/openbao/audit.log"
    mode      = "0600"
  }
}
