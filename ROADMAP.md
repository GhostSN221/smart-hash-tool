# Roadmap

## Now

- [x] 12 hash formats, detection, cracking, generation
- [x] HIBP lookup and rule engine
- [x] CLI + FastAPI
- [x] Repository / CI-log scanner
- [x] Kubernetes Secrets and ConfigMaps scanner
- [x] SARIF output and GitHub Action
- [x] Apache 2.0 license and governance docs

## Next

- [ ] SARIF upload as a first-class GitHub Code Scanning integration
- [ ] Helm chart and Kubernetes Job manifest
- [ ] Prometheus / OpenTelemetry metrics
- [ ] Policy-as-code integration (OPA / Kyverno)
- [ ] Detectors for additional secret formats
- [ ] bcrypt, argon2 and scrypt support for salted hashes

## Later

- [ ] Distributed workers for large audits
- [ ] Multi-tenant result storage
- [ ] Signed releases, SBOM and SLSA provenance
- [ ] Fuzzing and independent security review
- [ ] At least two co-maintainers from different organizations
- [ ] CNCF Sandbox application

The CNCF path and current gaps are documented in [docs/cncf.md](docs/cncf.md).
