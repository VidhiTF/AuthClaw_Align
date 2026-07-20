# ACL-21 evidence export format v2

`authclaw.audit.export.v2` is a JSON artifact containing:

- `manifest`: tenant, contiguous sequence range, record count, starting anchor,
  final chain root, selection markers, control links, SHA-256 proof metadata,
  trusted signing-key ID, signing algorithm, and verifier instructions.
- `records`: ordered PostgreSQL records. Each v2 record carries
  `tenant_sequence`, `chain_version`, `canonical_payload`, `prior_hash`, and
  `integrity_hash`.
- `digest`: SHA-256 of canonical JSON `{manifest, records}`.
- `signature`: Ed25519 signature over the same canonical bytes.

The verifier requires an external JSON registry:

```json
{
  "release-key-2026-07": {
    "public_key": "<base64 raw 32-byte Ed25519 public key>",
    "status": "active"
  }
}
```

Run:

```text
python backend/scripts/verify_audit_export.py --trusted-keys trusted-keys.json export.json
```

An embedded public key is never a trust root. Unknown, revoked, malformed, or
wrong keys fail verification.

## Filtering

Action, framework, and time filters identify selected evidence records. The
export retains every intermediate sequence from the first selected record
through the last selected record. Selected IDs are listed in
`manifest.selection.selected_record_ids`; retained intermediate rows are proof
records, not additional filter matches.

## Verification

Verification fails for a bad signature or digest; a modified canonical payload;
a missing, repeated, reordered, or cross-tenant record; a broken sequence or
prior-hash link; inconsistent anchors/counts; or an untrusted signing key.
