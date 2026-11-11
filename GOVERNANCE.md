# Governance

This document describes how the project is governed today and the path toward
a neutral, community-run project.

## Maintainers

Maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md). They are responsible
for:

- reviewing and merging pull requests;
- cutting releases and signing artifacts;
- managing security reports;
- keeping the roadmap and documentation current;
- upholding the code of conduct.

## Decision making

The project uses **lazy consensus**:

1. A proposal is made in a GitHub issue or pull request.
2. If no maintainer objects within 5 working days, it is accepted.
3. If there is disagreement, maintainers discuss in the issue and seek a
   consensus. If consensus is not possible, maintainers vote; a simple
   majority wins.
4. Security fixes may bypass the 5-day window when disclosure risk requires it.

## Becoming a maintainer

A contributor can be nominated by an existing maintainer after a sustained
record of:

- high-quality pull requests and reviews;
- tests and documentation for new behavior;
- respectful, constructive participation;
- understanding of the security and ethical constraints of the project.

New maintainers are approved by lazy consensus of the current maintainers. We
explicitly seek maintainers from different organizations to keep the project
neutral.

## Neutral home

The long-term goal is a neutral home (CNCF Sandbox, then incubation) with
maintainers from multiple organizations. The project is Apache 2.0 licensed and
does not depend on a proprietary service.

## Code of conduct

All participants must follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

Security reports follow [SECURITY.md](SECURITY.md). Do not open public issues
for vulnerabilities or real credentials.

## Roadmap and releases

The roadmap is in [ROADMAP.md](ROADMAP.md). Releases follow semantic versioning
and include a changelog, signed tags, and a software bill of materials (SBOM).
