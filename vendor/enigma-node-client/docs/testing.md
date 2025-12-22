# Testing

Integration tests spin up an in-process registry server from `enigma-node-registry` to exercise the client over HTTP. They register a dummy identity, resolve it back, check presence, and verify node listing. Negative tests cover input validation and error propagation on bad endpoints.
