Distribution and trust model

Official releases
- Artifacts are built from tags with scripts/release_build.sh using locked dependencies.
- Release workflow publishes enigma-daemon and enigma-cli binaries, SHA256SUMS, and BUILDINFO.json.
- SHA256SUMS is signed with minisign when a signing key is available. Without a key, SHA256SUMS.unsigned is uploaded.
- Verify by checking BUILDINFO.json against the tagged commit, validating minisign signatures, and comparing SHA256SUMS with local hashes.

Community distros
- Forks may change defaults, branding, or feature sets but must publish their own keys and manifests.
- Community binaries should be renamed to avoid confusion with official artifacts and must not reuse the official signing key.
- Trust the distro you build or verify; treat unsigned artifacts as untrusted.

Provenance and verification
- Dependencies are locked; CI and release builds run with --locked.
- To verify an official release locally:
  1) minisign -Vm SHA256SUMS -P <public-key> (or use SHA256SUMS.unsigned if no signature was produced)
  2) sha256sum -c SHA256SUMS
  3) Compare BUILDINFO.json with the tag, rustc/cargo versions, and the recorded target triple.
- scripts/release_build.sh documents the deterministic build steps; rerun it to reproduce dist/ locally.

Governance sketch
- Maintainers hold release keys and rotate them on compromise; compromised keys are revoked and announced.
- Security disclosures follow coordinated disclosure; report privately to maintainers before publicizing.
- No auto-deploy: artifacts are published only from tagged builds after verification.
