# Vulnerable Archive - Security Demo App

This is a **deliberately vulnerable** Django application designed to demonstrate both traditional web vulnerabilities and emerging risks associated with Large Language Model (LLM) integrations.

**WARNING: DO NOT RUN THIS APPLICATION IN A PRODUCTION ENVIRONMENT OR ON A PUBLICLY ACCESSIBLE SERVER.**

## Features

- **Website Archiving**: Save URLs, titles, and HTML content.
- **User Management**: Register and login.
- **AI Integration**: Ask questions about your data, generate summaries, and enrich content using a local LLM.

## Verify Fixes

A comprehensive, automated security auditing script is provided to verify both the vulnerabilities and their implemented mitigations. 

The audit tool seamlessly leverages Docker Compose to toggle the codebase between its vulnerable and secure states, executing the exploit suite in isolation and generating cleanly formatted Markdown reports.

### Running the Audit

Ensure you have Docker and Docker Compose installed, then run the audit script from the root directory:

```bash
# Test the original vulnerable state (generates before_fix_report.md)
./run_security_audit.sh before

# Test the fully patched secure state (generates after_fix_report.md)
./run_security_audit.sh after

# Run both states sequentially and generate the complete Remediation Report
./run_security_audit.sh all
```

### Generated Reports
Once the script completes, all results are output to the `reports/` directory:
1. `reports/before_fix_report.md`: Raw exploit execution against the vulnerable code.
2. `reports/after_fix_report.md`: Proof of mitigation (all exploits blocked) against the patched code.
3. `reports/vulnerability_remediation_report.md`: A detailed breakdown outlining the 10 critical vulnerabilities discovered, where they were located, and exactly how they were patched.
