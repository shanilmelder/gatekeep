# Host.Worker (AD-10): creates, rotates and deletes Tenant keys, wraps the token
# protection key, decrypts social, email and payload, and signs off-server records
# with dep-records. It can't touch Deployment keys other than to use them, or export.

# Create, rotate, configure for deletion, delete and read. The globs also reach
# /config, /import, /import_version and /trim, so the parameters those need to export,
# import known material or retire versions are denied.
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

path "transit/datakey/wrapped/tpk-*" {
  capabilities = ["update"]
}

path "transit/decrypt/social-*" {
  capabilities = ["update"]
}

path "transit/decrypt/email-*" {
  capabilities = ["update"]
}

path "transit/decrypt/payload-*" {
  capabilities = ["update"]
}

path "transit/decrypt/dep-email" {
  capabilities = ["update"]
}

path "transit/decrypt/dep-payload" {
  capabilities = ["update"]
}

# Off-server records (AD-17).
path "transit/sign/dep-records" {
  capabilities = ["update"]
}

path "transit/verify/dep-records" {
  capabilities = ["update"]
}

path "transit/keys/dep-records" {
  capabilities = ["read"]
}

# The orphan sweep (Story 2.4) lists key names. It reads only sig- and mgmt- keys, through the
# paths above; listing reveals names, never key material.
path "transit/keys" {
  capabilities = ["list"]
}
