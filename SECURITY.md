# Security Policy

## Supported versions

Security fixes are provided for the latest release and the `main` branch.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability or a real credential.

Use GitHub's private vulnerability reporting:

<https://github.com/GhostSN221/smart-hash-tool/security/advisories/new>

Include:

- affected version or commit;
- a minimal reproduction;
- impact and suggested fix, if known;
- whether the issue is already public.

We aim to acknowledge reports within 3 business days and to provide a remediation
plan within 10 business days. Timelines are best effort for a small project.

## Scope

In scope:

- the CLI, API and credential scanner;
- path traversal, command injection, unsafe deserialization;
- credential leakage in reports or logs;
- denial of service through unbounded input or resource use;
- bypasses of the API key or wordlist sandbox.

Out of scope:

- using the tool against systems without authorization;
- reports that require a real production credential;
- social engineering.

## Safe research

- Test only against systems and data you own or are explicitly authorized to test.
- Redact real secrets and personal data from reports.
- Do not include real credentials in issues, pull requests or test fixtures.

## Disclosure

We will coordinate disclosure with the reporter. Credit is given unless the
reporter prefers to remain anonymous.
