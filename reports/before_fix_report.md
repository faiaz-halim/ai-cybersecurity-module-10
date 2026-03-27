# Pre-Remediation Vulnerability Scan Report

## Overview
This report documents the security posture of the `vulnerable_archive` application prior to remediation. The test suite aggressively targets 9 specific vulnerability vectors encompassing both traditional web vulnerabilities and LLM-specific injection risks.

## Raw Test Output
```text
Found 11 test(s).
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
[SQLi Data Exfil] Response status: 200, Blocked: False
.[IDOR Edit] Archive Modified: True
.[JWT] Hardcoded Secret Exploited - Successfully decoded token: {'user_id': 1, 'username': 'user_a', 'exp': 1774723819}
.[IDOR] View Other User Archive - Response status: 200
[IDOR] Edit Other User Archive - Response status: 200
.[IDOR] Delete Other User Archive - Response status: 200
[LLM Injection] Prompt Injection - Response status: 200, Blocked: False
..[Path Traversal] File Write - Response status: 200, Blocked: False
.[SQLi] Search SQLi - Response status: 200, Blocked: False
.[SQLi via LLM] Ask Database SQLi - Response status: 200, Blocked: False
.[SSRF] Internal IP Access - Response status: 302, Blocked: False
.[SSRF via LLM] Enrich Archive - Response status: 200, Blocked: False
.[XSS] Content Display - Response status: 200, Blocked: False

----------------------------------------------------------------------
Ran 11 tests in 4.022s

OK
Destroying test database for alias 'default'...
```
