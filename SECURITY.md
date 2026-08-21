# Security policy

## Reporting a vulnerability

Do not disclose exploitable vulnerabilities, credentials, sensitive case data, or unsafe target URLs in a public issue. Use GitHub's private vulnerability reporting feature for this repository when available, or contact the repository owner privately through their GitHub profile.

Include the affected version, reproduction steps, impact, and any suggested mitigation. Remove real investigation data and secrets from examples.

Generated evidence can contain sensitive URLs, filenames, identifiers, and response metadata. Keep case output outside the repository, retain the supplied ignore rules, and inspect `git status` before committing. The tracked real-job seed must remain private unless its publication is intentional; deleting it from a later commit does not remove it from Git history.

## Operational scope

Leakscan is designed for authorized investigation of public references and metadata. It does not authorize access to restricted systems or retrieval of exposed archive contents. Operators are responsible for applicable laws, terms of service, evidence handling, and takedown procedures.
