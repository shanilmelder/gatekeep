# Host.Hosted (AD-10): signs with Signing Keys, encrypts totp and payload, decrypts
# totp and social, computes the Tenant hmac and unwraps the token protection key.
# It can't use Management keys (AD-33), create, rotate or delete any key, or export.

# Signing Keys, and their public halves for JWKS.
path "transit/sign/sig-*" {
  capabilities = ["update"]
}

path "transit/keys/sig-*" {
  capabilities = ["read"]
}

path "transit/encrypt/totp-*" {
  capabilities = ["update"]
}

path "transit/encrypt/payload-*" {
  capabilities = ["update"]
}

path "transit/decrypt/totp-*" {
  capabilities = ["update"]
}

path "transit/decrypt/social-*" {
  capabilities = ["update"]
}

# Unwraps the token protection key that Host.Worker wrapped.
path "transit/decrypt/tpk-*" {
  capabilities = ["update"]
}

path "transit/hmac/hmac-*" {
  capabilities = ["update"]
}
