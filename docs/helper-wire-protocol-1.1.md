# Helper wire protocol 1.1 freeze

Helper protocol 1.1 is frozen for release 0.7.0. The service and updater must
continue to exchange the exact helper-facing JSON shape shipped by the previous
release. This includes field names and order, omission behavior, schema version,
enum spellings, validation rules, pretty-JSON serialization, and the checksum of
each envelope body.

The frozen documents are:

- `updates/committed.json`;
- the preinstall request and receipt envelopes; and
- active, terminal, and failed update transaction envelopes, including their
  non-empty timelines.

Attempt correlation, retry metadata, checkpoint delivery receipts, failure-event
receipts, and transaction-trace receipts are service-owned state. They are stored
only in the attempt store (`updates/attempts` and `updates/attempt-history`) and
must never be added to, or persisted by rewriting, a helper-owned document.
Telemetry may read helper-owned documents to reconstruct events.

## Required compatibility gate

The `helper_wire_compat` test is an explicit step in the required Rust validation
job used by the release workflow. It proves both directions:

1. Release 0.7.0 constructs and serializes each helper-facing document. A pinned,
   independent protocol 1.1 decoder with `deny_unknown_fields` decodes it,
   validates schema/checksum, and the serialized bytes must equal the golden
   fixture.
2. Release 0.7.0 decodes and validates every protocol 1.1 golden fixture.

The committed-state case constructs a fresh baseline and also loads the retained
fixture, then requires identical canonical bytes and checksum.

The fixture files under
`crates/lsb-seawork-update/fixtures/protocol-1.1/` are immutable release evidence.
Their SHA-256 digests are pinned in the test. Do not refresh snapshots or update
the pinned digests for an ordinary service release. Any fixture change requires
an explicit helper protocol migration, a new protocol version, and review of both
service-to-helper and helper-to-service compatibility.
