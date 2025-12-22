# Design

The client lives in its own crate to avoid pulling server-side dependencies or binaries into applications like `enigma-messenger`. By reusing `enigma-node-types`, the client guarantees wire-level compatibility and strict decoding while keeping the binary footprint small. Safe defaults enforce bounded timeouts and capped response sizes to avoid unbounded waits or memory growth. URLs are constructed defensively to prevent malformed requests, and input validation rejects invalid user IDs before network calls.
