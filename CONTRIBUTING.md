# Contributing

Start with a reproducer and an invariant, not a new green badge. Run `pytest` and add tests that fail before the fix. Use only synthetic or lawfully redistributable fixtures: never submit licensed PDKs, proprietary reports, customer IP, real chip deliveries, keys or foundry credentials. Keep report adapters conservative and document their supported vendor/version contract.

Changes to hash encoding, event schemas, signature domains or trust semantics require explicit versioning and migration design. Do not silently reinterpret historical evidence. Maintain the distinction between integrity, execution authenticity, historical gate validity, current-design freshness and foundry acceptance.

The project is Apache-2.0. Contributions are accepted under that license. For unreported security problems, follow SECURITY.md rather than posting exploit-bearing production data publicly. Review docs/ROADMAP.md for the intended next acceptance criteria.
