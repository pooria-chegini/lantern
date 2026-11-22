# LANtern architecture
Principles: **Read-Only by Default**, **Explainable Scoring**, **Human-Approved Remediation**.
Credentials are used once in memory and never stored. LANtern never pushes config.

Engines: Device Intelligence, Security Assessment, Risk & Scoring, Remediation & Verification.
Shared: Vendor Adapter Framework (`vendors/`), Rule Engine (`audit/checks.py`, `core/risk.py`), Historical Data & Audit (SQLite).

Scoring: weighted checks, 0-100. Severity derives from weight; confidence is a fixed per-check estimate;
accepted risk counts half, false positive is excluded. Scores are grep-based estimates, not a full review.
