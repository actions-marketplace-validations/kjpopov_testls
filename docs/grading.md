# Grading

Every scan gets a letter grade. It is testls' own model, documented here,
and is **not** compatible with SSL Labs grades: the same server can get a
different letter there.

The grade is shown only. It never changes the exit status; use `--fail-on`
for that.

## Letters

The worst counted finding caps the grade:

| Worst counted finding | Grade |
| --- | --- |
| `critical` | F |
| `high` | C |
| `medium` | B |
| `low` | A- |
| none | A or A+ |

With no counted finding the grade is **A+** when all of these hold, and
**A** otherwise:

- TLSv1.3 is offered
- no protocol older than TLSv1.2 is offered
- the reply to `GET /` sends a valid `Strict-Transport-Security` header
  with a `max-age` of at least one year (31536000 seconds)

Without an HTTP reply (`--profile quick`, `--starttls`, non-HTTP service)
the HSTS requirement is not met, so the best grade is A.

## Counted findings

- Severity `low` or worse; `info` and `ok` findings do not count.
- `policy.*` findings do not count: a compliance policy is your choice,
  not a property of the server.
- Suppressions (`.testls.toml`) and `--baseline` do **not** apply: the
  grade describes the server, not what you chose to accept.

## Markers

- **T**: the certificate is untrusted (`cert.untrusted`) or does not
  cover the host (`cert.hostname_mismatch`). Shown after the letter, e.g.
  `C T`. Both findings are `high`, so the letter is at most C.
- **incomplete**: a probe failed (a `*.error` or `*.incomplete` finding,
  or a protocol probe error). The grade may be better than the server
  deserves; rerun the scan.

## Reasons

Each grade comes with reasons for why it is not better: the ids of the
findings at the worst counted severity, or the A+ requirements that are
not met, plus a note when the grade is incomplete.

```text
Grade
  C T
    high findings: cert.hostname_mismatch, cert.untrusted
```

## Output

| Format | Where |
| --- | --- |
| `text` | `Grade` section after the findings |
| `json` | `grade` object, see [json-schema.md](json-schema.md#grade) |
| `sarif` | `runs[].properties.grades`, one entry per target |
| `junit` | `grade` property of each test suite |
| `markdown`, `html` | `Grade` column in the summary table and reasons per target |
| `csv` | A `scan.grade` row per target; the message holds grade and reasons |
