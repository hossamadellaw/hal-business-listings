# Security Policy

## Supported versions

Only the latest published [Release](https://github.com/hossamadellaw/hal-business-listings/releases) receives security fixes. Sites should stay current through the built-in updater.

## Reporting a vulnerability

**Primary channel — GitHub Private Vulnerability Reporting (enabled on this repository):**
Repository → **Security** tab → **Report a vulnerability**. Reports stay private between you and the maintainer until a fix is released.

Please include:

- Affected version (from the plugin header) and WordPress/PHP versions
- A minimal reproduction path (URL, role required, request/response)
- Impact assessment as you understand it

**Alternative channel:** the contact form at https://hossamadellaw.com

## Scope

In scope:

- The plugin code in this repository (PHP, JS, templates, workflow build)
- Exposure of confidential seller data (`_hal_bl_*` meta) or the Amelia API key
- The update pipeline (release integrity, asset authenticity)

Out of scope:

- Vulnerabilities in WordPress core, ACF, Elementor, WPML, or Amelia themselves — report upstream
- Reports that require a compromised wp-admin account or server-level access
- Automated scanner output without a demonstrated exploit path; denial-of-service

## Safe harbor

Good-faith research following this policy is welcomed. Do not access, modify, or exfiltrate real business or personal data while testing, and do not run availability attacks.

## Response targets

- Acknowledgement: within 48 hours
- Triage decision: within 7 days
- Fix or mitigation: severity-dependent, target 30 days for high severity

## Data handling note

Real seller contact data and Amelia credentials are private operational data. Never include live PII or API keys in reports or proof-of-concepts.
