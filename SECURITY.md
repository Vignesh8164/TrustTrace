# Security policy

TrustTrace is a local prototype for synthetic, harmless demonstrations. Do not submit real credentials, personal data, malware, destructive payloads, or real target information to the Attack Lab or issue tracker.

## Reporting

For a suspected vulnerability, do not open a public issue with exploit details. Contact the repository maintainer privately through the GitHub security-advisory mechanism or the maintainer's verified GitHub contact. Include a minimal reproduction, affected commit, impact, and suggested mitigation. Remove secrets from all reports.

## Scope and limitations

The default server binds to `127.0.0.1`, and the local MVP intentionally omits operator authentication. SQLite audit records are append-only by application behavior but are not cryptographically tamper-proof. Do not expose this service to a network or use it as a production enforcement gateway without authentication, authorization, protected storage, backups, rate limiting, and independent review.
