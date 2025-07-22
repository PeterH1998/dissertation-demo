### 🛡️ Privacy Scan Report

**Snyk**

- Vulnerabilities: **{{ total_vulns }}**
- High severity: **{{ high_vulns }}**

**GitLeaks**

- Secrets found: **{{ secrets_count }}**

**OWASP ZAP**

- High: **{{ zap_high }}**, Medium: **{{ zap_medium }}**, Low: **{{ zap_low }}**

**PII Scanner**

- Emails: **{{ email_count }}**, Phones: **{{ phone_count }}**, SSNs: **{{ ssn_count }}**

<details>
<summary>Full JSON reports</summary>

- [Snyk report](artifact://snyk-report.json)
- [GitLeaks report](artifact://gitleaks-report.json)
- [ZAP JSON report](artifact://zap-report.json)
- [PII report](artifact://pii-report.json)

</details>
