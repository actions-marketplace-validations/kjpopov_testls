# JSON report schema

`testls --format json` prints one JSON document to stdout when the scan
finishes. This page describes schema version **1**.

## Stability

- `schema_version` changes when a field is removed, renamed, or changes
  meaning or type.
- New fields may be added without a version bump. Consumers should ignore
  fields they do not know.
- Finding `id`s are stable. New ids may appear in any release.
- Scan errors (exit code 2) print a message to stderr and no JSON.
- The exit code is the same as for text output (see `--fail-on`).

## Document

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | integer | Schema version, currently `1` |
| `tool.name` | string | Always `"testls"` |
| `tool.version` | string | testls version |
| `target.input` | string | Target as given on the command line |
| `target.address` | string | Socket address that was scanned, e.g. `"192.0.2.1:443"` or `"[2001:db8::1]:443"` |
| `target.sni` | string or null | SNI name sent, `null` if none |
| `started_at` | integer | Scan start, Unix time in seconds |
| `protocols` | array | One [protocol](#protocol) per probed version, oldest first |
| `ciphers` | array | One [cipher list](#cipher-list) per offered version |
| `certificate` | object | The [certificate chain](#certificate-chain) |
| `findings` | array | [Findings](#finding), most severe first |

### Protocol

| Field | Type | Description |
| --- | --- | --- |
| `version` | string | `"SSLv2"`, `"SSLv3"`, `"TLSv1.0"`, `"TLSv1.1"`, `"TLSv1.2"`, or `"TLSv1.3"` |
| `status` | string | `"offered"`, `"not_offered"`, or `"error"` |
| `error` | string | Only when `status` is `"error"` |

### Cipher list

| Field | Type | Description |
| --- | --- | --- |
| `protocol` | string | Protocol version, as above |
| `order` | string or null | `"server"` or `"client"` preference; `null` if fewer than two suites were accepted or enumeration failed |
| `suites` | array | Suites in the server's order of choice |
| `suites[].id` | string | Hex code point: `"0xc02f"`, or six digits for SSLv2 cipher specs (`"0x010080"`) |
| `suites[].name` | string | IANA name |
| `suites[].severity` | string | Severity of the suite, see [Finding](#finding) |
| `error` | string | Only when enumeration failed; `suites` is then empty |

### Certificate chain

| Field | Type | Description |
| --- | --- | --- |
| `protocol` | string or null | Version of the handshake that fetched the chain; `null` on error |
| `chain` | array | Certificates as sent by the server, leaf first |
| `chain[].subject` | string | Subject distinguished name |
| `chain[].issuer` | string | Issuer distinguished name |
| `chain[].not_before` | integer | Start of validity, Unix time |
| `chain[].not_after` | integer | End of validity, Unix time |
| `chain[].names` | array of strings | DNS names and IP addresses from the subject alternative names |
| `chain[].key` | string | Key algorithm and size, e.g. `"RSA 2048 bits"` |
| `chain[].error` | string | Only for a certificate that cannot be parsed; the other fields are then absent |
| `error` | string | Only when the chain could not be retrieved; `chain` is then empty |

### Finding

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Stable identifier, e.g. `"protocol.tls10"`, `"cert.untrusted"` |
| `severity` | string | `"info"`, `"low"`, `"medium"`, `"high"`, or `"critical"` |
| `message` | string | Human-readable description; wording may change |

Suite severities can also be `"ok"`. Findings with severity `ok` are not
reported.

## Example

Abbreviated:

```json
{
  "schema_version": 1,
  "tool": { "name": "testls", "version": "0.1.0" },
  "target": { "input": "example.com", "address": "192.0.2.1:443", "sni": "example.com" },
  "started_at": 1792835801,
  "protocols": [
    { "version": "TLSv1.2", "status": "offered" },
    { "version": "TLSv1.3", "status": "offered" }
  ],
  "ciphers": [
    {
      "protocol": "TLSv1.3",
      "order": "server",
      "suites": [
        { "id": "0x1302", "name": "TLS_AES_256_GCM_SHA384", "severity": "ok" }
      ]
    }
  ],
  "certificate": {
    "protocol": "TLSv1.3",
    "chain": [
      {
        "subject": "CN=example.com",
        "issuer": "CN=Example CA",
        "not_before": 1767225600,
        "not_after": 1798761600,
        "names": ["example.com"],
        "key": "EC 256 bits"
      }
    ]
  },
  "findings": [
    { "id": "protocol.no_tls13", "severity": "info", "message": "..." }
  ]
}
```
