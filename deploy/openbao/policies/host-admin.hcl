# Host.Admin (AD-10): creates Signing and Management keys, signs with Management keys
# (AD-33), encrypts social, email and payload, and computes the Deployment hmac.
# It decrypts nothing, and it has no read: the public halves come back from create.
#
# A grant on transit/keys/sig-* also reaches transit/keys/sig-*/rotate, because a
# policy glob can't stop at the end of a name. Requiring and pinning `type` refuses
# config, trim and import, and a rotate with no parameters, but OpenBao ignores an
# unknown `type` on rotate, so a crafted request can still rotate these keys (T-45).

path "transit/keys/sig-*" {
  capabilities        = ["update"]
  required_parameters = ["type"]
  allowed_parameters = {
    "type" = ["rsa-3072"]
  }
  denied_parameters = {
    "exportable"             = []
    "allow_plaintext_backup" = []
  }
}

path "transit/keys/mgmt-*" {
  capabilities        = ["update"]
  required_parameters = ["type"]
  allowed_parameters = {
    "type" = ["rsa-3072"]
  }
  denied_parameters = {
    "exportable"             = []
    "allow_plaintext_backup" = []
  }
}

path "transit/sign/mgmt-*" {
  capabilities = ["update"]
}

path "transit/encrypt/social-*" {
  capabilities = ["update"]
}

path "transit/encrypt/email-*" {
  capabilities = ["update"]
}

path "transit/encrypt/payload-*" {
  capabilities = ["update"]
}

# Deployment keys for Admin flows: invites and the Deployment email provider.
path "transit/encrypt/dep-email" {
  capabilities = ["update"]
}

path "transit/encrypt/dep-payload" {
  capabilities = ["update"]
}

path "transit/hmac/dep-hmac" {
  capabilities = ["update"]
}
