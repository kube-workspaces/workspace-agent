`management-v1.json` is byte-identical to the API management grant test vector.
It uses an intentionally public all-zero test seed and synthetic identities;
never provision the fixture key in an installation. The vector proves Go-issued
Ed25519 compact JWS grants are independently verified by the Rust guest library.
