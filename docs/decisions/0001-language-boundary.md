**Decision: Go services with a Rust core**

The user selected Go for coordinator/workers and Rust for the core. This supersedes the Python/FastAPI/Pydantic application choices in the initial architecture draft.

Go owns service lifecycle, CLI, future PostgreSQL scheduling, network clients, and worker orchestration. Rust owns task/evidence types and deterministic validation. The laboratory is a small Go HTTP service to minimize initial dependencies; target-language support remains independent of the harness implementation.

The initial interface is a versioned JSON subprocess protocol. This gives one authoritative validator and simple process failure behavior without FFI or a permanently exposed RPC service. Startup overhead is acceptable for this contract/lab milestone and should be measured before changing the boundary.

Rust provides implementation-level memory safety; it is not a substitute for isolating untrusted target code. No arbitrary target execution is implemented in milestone 1.

Use a persistent worker protocol or authenticated local RPC later only if measurements justify it. Preserve schema/protocol versioning and keep security-policy decisions in the Rust core as they are implemented.
