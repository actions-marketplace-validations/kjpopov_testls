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
| `key_exchange` | array | One [key exchange](#key-exchange) per offered version |
| `certificate` | object | The [certificate chain](#certificate-chain) |
| `http` | object | [HTTP headers](#http-headers) of the reply to `GET /` |
| `revocation` | object or null | [Revocation](#revocation) check with `--revocation`; `null` without it |
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

### Key exchange

| Field | Type | Description |
| --- | --- | --- |
| `protocol` | string | Protocol version, as above |
| `group_order` | string or null | `"server"` or `"client"` preference; `null` if fewer than two groups were accepted or the probe failed |
| `groups` | array | Supported groups (named curves, FFDHE, ML-KEM) in the server's order of choice; empty when no ECDHE suite is accepted |
| `groups[].id` | string | Hex code point, e.g. `"0x11ec"` |
| `groups[].name` | string | IANA name, e.g. `"X25519MLKEM768"` |
| `groups[].severity` | string | Severity of the group, see [Finding](#finding) |
| `dh_bits` | integer or null | Size of the ephemeral DH prime offered with DHE suites (TLSv1.2 and older); `null` without DHE |
| `error` | string | Only when the probe failed; `groups` is then empty |

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
| `ocsp` | object or null | Stapled OCSP response for the leaf; `null` on error |
| `ocsp.stapled` | boolean | The server stapled a response |
| `ocsp.status` | string or null | `good`, `revoked`, `unknown`, or `invalid`; `null` when not stapled |
| `ocsp.produced_at` | integer | When the response was signed, Unix time; only for a verified response |
| `ocsp.this_update` | integer | Start of the validity interval, Unix time; only for a verified response |
| `ocsp.next_update` | integer | End of the validity interval, Unix time; absent when the responder gave none |
| `ocsp.revocation_time` | integer | Only when `revoked`: revocation time, Unix time |
| `ocsp.revocation_reason` | string | Only when `revoked` with a reason: RFC 5280 `CRLReason` name, e.g. `"keyCompromise"` |
| `ocsp.error` | string | Only when `invalid`: why the response failed to parse or verify |
| `error` | string | Only when the chain could not be retrieved; `chain` is then empty |

### HTTP headers

One `GET /` request is sent over a full handshake; redirects are not followed.

| Field | Type | Description |
| --- | --- | --- |
| `status` | integer or null | HTTP status code; `null` on error |
| `headers` | object | Each security header by lowercase name (`strict-transport-security`, `content-security-policy`, `x-frame-options`, `x-content-type-options`, `referrer-policy`), first value or `null` when not set; empty on error |
| `hsts` | object or null | Parsed `Strict-Transport-Security` policy from the first header; `null` when missing or invalid |
| `hsts.max_age` | integer | `max-age` in seconds |
| `hsts.include_subdomains` | boolean | `includeSubDomains` is present |
| `hsts.preload` | boolean | `preload` is present |
| `hsts.preload_eligible` | boolean | `max-age` is at least one year and both `includeSubDomains` and `preload` are present |
| `error` | string | Only when the headers could not be fetched, e.g. the server does not speak HTTP |

### Revocation

Only with `--revocation`: the OCSP responders named in the leaf certificate
are queried first, then its CRLs are downloaded, until one gives a verifiable
answer. Only `http://` URLs are used.

| Field | Type | Description |
| --- | --- | --- |
| `checks` | array | Each attempt in the order made; empty when the certificate names no HTTP OCSP responder or CRL |
| `checks[].method` | string | `ocsp` or `crl` |
| `checks[].url` | string | URL that was queried |
| `checks[].status` | string | `good`, `revoked`, `unknown`, or `error` |
| `checks[].this_update` | integer | Start of the validity interval, Unix time; absent on error |
| `checks[].next_update` | integer | End of the validity interval, Unix time; absent when none was given |
| `checks[].revocation_time` | integer | Only when `revoked`: revocation time, Unix time |
| `checks[].revocation_reason` | string | Only when `revoked` with a reason: RFC 5280 `CRLReason` name |
| `checks[].error` | string | Only on `error`: why fetching or verification failed |
| `error` | string | Only when no check could be made, e.g. the chain could not be retrieved |

### Finding

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Stable identifier, e.g. `"protocol.tls10"`, `"cert.untrusted"` |
| `severity` | string | `"info"`, `"low"`, `"medium"`, `"high"`, or `"critical"` |
| `message` | string | Human-readable description; wording may change |

Suite and group severities can also be `"ok"`. Findings with severity `ok` are not
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
  "key_exchange": [
    {
      "protocol": "TLSv1.3",
      "group_order": "server",
      "groups": [
        { "id": "0x11ec", "name": "X25519MLKEM768", "severity": "ok" },
        { "id": "0x001d", "name": "x25519", "severity": "ok" }
      ],
      "dh_bits": null
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
    ],
    "ocsp": {
      "stapled": true,
      "status": "good",
      "produced_at": 1792918114,
      "this_update": 1792918114,
      "next_update": 1793522914
    }
  },
  "http": {
    "status": 200,
    "headers": {
      "content-security-policy": null,
      "referrer-policy": "no-referrer",
      "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY"
    },
    "hsts": { "max_age": 63072000, "include_subdomains": true, "preload": true, "preload_eligible": true }
  },
  "revocation": {
    "checks": [
      { "method": "ocsp", "url": "http://ocsp.example.net/", "status": "good", "this_update": 1792918114, "next_update": 1793522914 }
    ]
  },
  "findings": [
    { "id": "protocol.no_tls13", "severity": "info", "message": "..." }
  ]
}
```
