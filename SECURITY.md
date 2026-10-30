# Security

These agents run inside customers' networks, so we take reports seriously.

**Reporting a vulnerability:** email support@certhalo.com with (subject: "Security"), with the details and how to reproduce it. Please don't open a public issue for security problems. We'll acknowledge your report within 3 working days and keep you updated until it's fixed.

**Design rules the agents follow** (see the README for details):

- They only ever send certificates, which are public, never private keys or anything else from your servers; a report containing a private key is refused by the agent and by CertHalo.
- Their only outbound connection is to CertHalo over HTTPS.
- They use Agent keys, which can only send reports for one workspace.
- Releases include SHA-256 checksums; the Docker image is built in GitHub Actions from this repository.
