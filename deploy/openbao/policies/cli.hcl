# Gatekeep.Cli (AD-10): creates, rotates, rewraps and deletes keys, encrypts social
# and email, and signs and verifies off-server records. Deployment keys can be
# created and rotated but not deleted. Nobody may export.

path "transit/keys/sig-*" {
  capabilities = ["update", "read", "delete"]
  denied_parameters = {
    "exportable"             = []
    "allow_plaintext_backup" = []
    "ciphertext"             = []
    "public_key"             = []
    "min_decryption_version" = []
    "min_available_version"  = []
  }
}

path "transit/keys/mgmt-*" {
  capabilities = ["update", "read", "delete"]
  denied_parameters = {
    "exportable"             = []
    "allow_plaintext_backup" = []
    "ciphertext"             = []
    "public_key"             = []
    "min_decryption_version" = []
    "min_available_version"  = []
  }
}

path "transit/keys/totp-*" {
  capabilities = ["update", "read", "delete"]
  denied_parameters = {
    "exportable"             = []
    "allow_plaintext_backup" = []
    "ciphertext"             = []
    "public_key"             = []
    "min_decryption_version" = []
    "min_available_version"  = []
  }
}

path "transit/keys/social-*" {
  capabilities = ["update", "read", "delete"]
  denied_parameters = {
    "exportable"             = []
    "allow_plaintext_backup" = []
    "ciphertext"             = []
    "public_key"             = []
    "min_decryption_version" = []
    "min_available_version"  = []
  }
}

path "transit/keys/email-*" {
  capabilities = ["update", "read", "delete"]
  denied_parameters = {
    "exportable"             = []
    "allow_plaintext_backup" = []
    "ciphertext"             = []
    "public_key"             = []
    "min_decryption_version" = []
    "min_available_version"  = []
  }
}

path "transit/keys/payload-*" {
  capabilities = ["update", "read", "delete"]
  denied_parameters = {
    "exportable"             = []
    "allow_plaintext_backup" = []
    "ciphertext"             = []
    "public_key"             = []
    "min_decryption_version" = []
    "min_available_version"  = []
  }
}

path "transit/keys/hmac-*" {
  capabilities = ["update", "read", "delete"]
  denied_parameters = {
    "exportable"             = []
    "allow_plaintext_backup" = []
    "ciphertext"             = []
    "public_key"             = []
    "min_decryption_version" = []
    "min_available_version"  = []
  }
}

path "transit/keys/tpk-*" {
  capabilities = ["update", "read", "delete"]
  denied_parameters = {
    "exportable"             = []
    "allow_plaintext_backup" = []
    "ciphertext"             = []
    "public_key"             = []
    "min_decryption_version" = []
    "min_available_version"  = []
  }
}

# Deployment keys: create, rotate and read only. deletion_allowed is denied, so they
# can't be made deletable.
path "transit/keys/dep-*" {
  capabilities = ["update", "read"]
  denied_parameters = {
    "exportable"             = []
    "allow_plaintext_backup" = []
    "ciphertext"             = []
    "public_key"             = []
    "min_decryption_version" = []
    "min_available_version"  = []
    "deletion_allowed"       = []
  }
}

path "transit/rewrap/totp-*" {
  capabilities = ["update"]
}

path "transit/rewrap/social-*" {
  capabilities = ["update"]
}

path "transit/rewrap/email-*" {
  capabilities = ["update"]
}

path "transit/rewrap/payload-*" {
  capabilities = ["update"]
}

path "transit/rewrap/tpk-*" {
  capabilities = ["update"]
}

path "transit/rewrap/dep-email" {
  capabilities = ["update"]
}

path "transit/rewrap/dep-payload" {
  capabilities = ["update"]
}

path "transit/encrypt/social-*" {
  capabilities = ["update"]
}

path "transit/encrypt/email-*" {
  capabilities = ["update"]
}

path "transit/encrypt/dep-email" {
  capabilities = ["update"]
}

# Off-server records (AD-17, AD-31).
path "transit/sign/dep-records" {
  capabilities = ["update"]
}

path "transit/verify/dep-records" {
  capabilities = ["update"]
}
