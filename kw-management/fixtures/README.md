`management-v1.json` is byte-identical to the API management grant test vector.
It uses an intentionally public all-zero test seed and synthetic identities;
never provision the fixture key in an installation. The vector proves Go-issued
Ed25519 compact JWS grants are independently verified by the Rust guest library.

`management-qga-v1.json` is the byte-identical QGA pilot transport
(`qga-pod-exec/v1`) vector: same public all-zero seed, a distinct
audience/issuer/grant type and a SYSTEM command request envelope. It proves the
Go-issued QGA grant and the exact staged request bytes are independently
verified by the Rust guest library; the runner additionally checks the request
bounds and this guest's enrolled workspace UID.
