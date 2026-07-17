# JSON schema (`schema_version: "1"`)

One schema is used in both directions and on both surfaces: the CLI's
`--json` output, and the WASM API's request/response. The version is a major
version only — it is bumped on any backward-incompatible change, and adding
optional fields is not one.

## Request

The WASM `generateClientConfig(requestJSON)` argument. The CLI builds the
same struct from flags.

```json
{
  "name": "probe01",
  "address": "10.0.4.20",
  "secret": "",
  "secret_length": 32,
  "secret_charset": "alnum-symbols",
  "nas_type": "other",
  "require_message_authenticator": true,
  "coa_note": false
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | yes | 1–64 chars of `A-Z a-z 0-9 . _ -`; becomes the clients.conf block label and the NPS `-Name` |
| `address` | string | yes | IPv4/IPv6 host address or CIDR prefix; CIDR host bits must be zero; zone IDs rejected |
| `secret` | string | no | non-empty means user-supplied, used as-is; empty/omitted means generate |
| `secret_length` | int | no | generation only; default 32, min 16, max 128 (NPS limit) |
| `secret_charset` | string | no | generation only; `alnum-symbols` (76 symbols, default) or `alnum` (62) |
| `nas_type` | string | no | emitted as FreeRADIUS `nas_type`; no NPS equivalent |
| `require_message_authenticator` | bool | no | **omitted means `true`** (hardening is the default on every surface) |
| `coa_note` | bool | no | append the CoA/Disconnect port note to both outputs |

## Result

The CLI's `--json` stdout document; in WASM it arrives wrapped as
`{"ok": true, "result": <Result>}` (errors: `{"ok": false, "error": "..."}`).

```json
{
  "schema_version": "1",
  "freeradius": "# FreeRADIUS 3.x client block — ...",
  "nps": "# Windows NPS RADIUS client — ...",
  "secret": "kFwzheGDtqfvSw~^_A+Gr,heNOaP.dpe",
  "secret_generated": true,
  "entropy_bits": 199,
  "warnings": []
}
```

| Field | Notes |
|---|---|
| `schema_version` | always `"1"` for this shape |
| `freeradius` | complete clients.conf block, ready to paste |
| `nps` | complete PowerShell registration, ready to paste |
| `secret` | the secret embedded in both outputs — treat the whole document as sensitive |
| `secret_generated` | `false` when the caller supplied the secret |
| `entropy_bits` | `floor(length × log2(charset size))`; omitted for user-supplied secrets |
| `warnings` | human-readable, non-fatal; omitted when empty |
