---
ovdb: 1
publish:
  - ./ovdb.yaml
  - ./ovdb-database.json
---

# Shipping logs OVDB publication

The descriptors above configure the intended publication of the immutable
native inGitDB database through OpenVaultDB. The endpoint is deployed and
verified (`deploymentVerified` in `manifest.json`); a new revision is served
after the OpenVaultDB provider pin moves to it. Original JSONL files remain the
only record storage authority.

