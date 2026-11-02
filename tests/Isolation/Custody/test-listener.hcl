# Test only, never in deploy/. Docker Desktop runs Linux containers from a Windows host,
# which can't reach a unix socket inside the container, so tests use this listener.
listener "tcp" {
  address     = "0.0.0.0:8210"
  tls_disable = true
}
