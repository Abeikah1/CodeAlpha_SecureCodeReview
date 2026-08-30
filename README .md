# CodeAlpha_SecureCodeReview

**CodeAlpha Cyber Security Internship — Task 3: Secure Coding Review**

## Contents
- `vulnerable_app.py` — a small Flask "notes" app, **deliberately** written
  with 7 real-world vulnerabilities, used as the subject of this audit.
  Each vulnerability is marked inline with a comment.
- `fixed_app.py` — the same app with every finding remediated, referenced
  directly by the report's "Fix" sections.
- `Secure_Coding_Review_Report.docx` — the formal audit report: scope,
  methodology, an executive summary table, and a detailed write-up of each
  finding (issue, impact, evidence, recommendation, fix).

## Methodology
Manual, line-by-line static source code review, checked against the
[OWASP Top 10 (2021)](https://owasp.org/Top10/) categories.

## Summary of findings

| # | Finding | Severity | OWASP Category |
|---|---|---|---|
| 1 | Hardcoded application secret key | High | A05:2021 Security Misconfiguration |
| 2 | Hardcoded admin credentials | Critical | A07:2021 Identification & Auth Failures |
| 3 | SQL Injection (login and search) | Critical | A03:2021 Injection |
| 4 | Broken access control (IDOR on notes) | High | A01:2021 Broken Access Control |
| 5 | Stored/Reflected XSS | High | A03:2021 Injection |
| 6 | Missing auth on admin route | Critical | A01:2021 Broken Access Control |
| 7 | Debug mode enabled, bound to all interfaces | Medium | A05:2021 Security Misconfiguration |

Full detail — evidence snippets, impact, and the exact fix for each — is in
`Secure_Coding_Review_Report.docx`.

## Why an intentionally vulnerable app?
A secure coding review needs a concrete subject to audit. Writing a small,
clearly-labeled, non-deployed sample (rather than auditing unrelated
third-party code without permission) keeps the exercise self-contained,
reproducible, and safe — nothing here is ever run against a live target.

## Author
Irene — CodeAlpha Cyber Security Internship, Task 3
