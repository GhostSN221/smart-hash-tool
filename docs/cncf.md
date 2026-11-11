# CNCF readiness

This document tracks the gap between the project today and a realistic CNCF
Sandbox application. It is based on the public `cncf/sandbox` requirements.

## Sandbox checklist

| Requirement | Status |
|---|---|
| Apache 2.0 license before applying | ✅ [LICENSE](../LICENSE) |
| `MAINTAINERS.md` with Name / GitHub ID / Company columns | ✅ [MAINTAINERS.md](../MAINTAINERS.md) |
| Code of conduct | ✅ [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) |
| Security policy | ✅ [SECURITY.md](../SECURITY.md) |
| Governance and decision process | ✅ [GOVERNANCE.md](../GOVERNANCE.md) |
| Reusable project (not a reference architecture) | ✅ credential scanner + CLI/API |
| Public roadmap | ✅ [ROADMAP.md](../ROADMAP.md) |
| Tests and CI | ✅ 103 tests, 87% coverage, GitHub Actions |
| Real adopters | ❌ [ADOPTERS.md](../ADOPTERS.md) is a template |
| Maintainers from multiple organizations | ❌ one maintainer today |
| Release process, signed artifacts, SBOM | ❌ roadmap |
| CNCF Sandbox application + TOC vote + Contribution Agreement | ❌ not applied |

## What CNCF evaluates

From the public `cncf/sandbox` README:

- license compliance **before** acceptance (Apache 2.0; BSL/GPL not accepted);
- a direct link to `MAINTAINERS.md` with the required columns;
- organization diversity of maintainers is considered;
- the project must be reusable, not a reference architecture;
- naming and trademark constraints;
- a TOC vote and a signed Contribution Agreement.

Sandbox applications are reviewed roughly every two months. Applying before the
project has adopters, maintainer diversity and a release process is unlikely to
succeed.

## Positioning for CNCF

The project is deliberately positioned as a **defensive credential hygiene
scanner**, not an offensive cracking tool:

- scans repositories, CI logs and Kubernetes Secrets/ConfigMaps;
- reports weak hashes, plaintext credentials and reused passwords;
- redacts plaintext secrets in findings;
- supports SARIF and CI policy gates;
- requires explicit authorization and has safe defaults.

This matters because a project whose primary use is attacking credentials is a
poor fit for CNCF, while a scanner that improves credential hygiene in
cloud-native supply chains is aligned with the security ecosystem.

## Next milestones

1. Real adopters and case studies.
2. A second and third maintainer from different organizations.
3. Helm chart, Kubernetes Job and OpenTelemetry metrics.
4. Signed releases, SBOM and SLSA provenance.
5. A public security review and fuzzing.
6. Apply for CNCF Sandbox after the above.

## References

- <https://github.com/cncf/sandbox>
- <https://contribute.cncf.io/projects/lifecycle/>
- <https://www.cncf.io/sandbox-projects/>
