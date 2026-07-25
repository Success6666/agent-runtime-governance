# Security Policy

## Supported versions

Security fixes are applied to the latest minor release. Applications should pin
an exact version and upgrade after reviewing the changelog.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository. Do not include
live credentials, production traces, webhook URLs, or customer data in a public
issue.

## Trust boundaries

- Prompt text is not an authorization boundary.
- Gating middleware fails closed; observing middleware cannot grant permission.
- Required approval without an explicit granted decision is denied.
- Replay skips middleware with external side effects.
- YAML uses safe loading and a strict schema.
- Python plugins and entry points execute trusted application code. Review and
  pin them as carefully as any direct dependency.
- Audit redaction is key-based. Applications must extend `sensitive_keys` for
  domain-specific secrets and should avoid placing secrets in positional args.
- OPA and Slack endpoints must come from trusted deployment configuration.

## Deployment guidance

Keep HMAC keys, webhook URLs, model credentials, and OPA credentials in a secret
manager. Restrict audit and snapshot file permissions. Use TLS for remote policy
and decision services. Avoid user-, tenant-, conversation-, or trace-based
Prometheus labels because they leak identity and create unbounded cardinality.
