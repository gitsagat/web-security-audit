# Fontes primárias

Ao atualizar esta skill ou checar uma CVE, partir destas fontes — não de blogs agregadores.

## Padrões e checklists

- OWASP Top 10:2025 — https://owasp.org/Top10/2025/
- OWASP API Security Top 10:2023 — https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP ASVS 5.0 (requisitos verificáveis, níveis L1–L3) — https://owasp.org/www-project-application-security-verification-standard/
- OWASP Web Security Testing Guide (WSTG) — https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheet Series (XSS, CSRF, SSRF, SQLi, XXE, Authentication, MFA, Session, REST, Mass Assignment, IDOR) — https://cheatsheetseries.owasp.org/
- CWE Top 25 — https://cwe.mitre.org/top25/
- NIST SP 800-63B (senhas e MFA) — https://pages.nist.gov/800-63-4/
- PortSwigger Web Security Academy (explicação e laboratórios por classe de falha) — https://portswigger.net/web-security
- Mozilla Web Security Guidelines / Observatory — https://developer.mozilla.org/en-US/observatory

## Vulnerabilidades e CVEs

- CISA KEV (exploradas ativamente; JSON em `known_exploited_vulnerabilities.json`) — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- OSV (API e banco multi-ecossistema) — https://osv.dev
- GitHub Advisory Database — https://github.com/advisories
- NVD — https://nvd.nist.gov
- Django security releases — https://www.djangoproject.com/weblog/ e https://docs.djangoproject.com/en/dev/releases/security/
- Next.js / Vercel advisories — https://github.com/vercel/next.js/security/advisories
- Spring Security advisories — https://spring.io/security
- PHP — https://www.php.net/ChangeLog-8.php
- Supabase: RLS e Security Advisor — https://supabase.com/docs/guides/database/postgres/row-level-security

## Referências usadas na pesquisa de 2026

- Django, releases de 03/02/2026 — https://djangoproject.com/weblog/2026/feb/03/security-releases
- Next.js, lote de maio/2026 — https://netlify.com/changelog/2026-05-08-react-nextjs-security-vulnerabilities/
- Next.js, lote de julho/2026 — https://www.netlify.com/changelog/2026-07-21-nextjs-security-vulnerabilities.md
- GHSA-267c-6grr-h53f — https://osv.dev/GHSA-267c-6grr-h53f
- PHP php2shell, alerta CISA — https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- Mini Shai-Hulud, FAQ Tenable — https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions
- Supply chain mai–jul/2026 — https://securityboulevard.com/2026/07/the-streak-continues-four-more-supply-chain-attacks-hit-npm-and-pypi/
- lxml CVE-2026-41066 — https://security.snyk.io/vuln/SNYK-PYTHON-LXML-16119103
- Supabase, exposição sistêmica (UpGuard, set/2026) — https://www.upguard.com/blog/everything-everywhere-systemic-data-exposure-in-supabase-apps
- KEV Cisco SD-WAN (out/2026) — https://thehackernews.com/2026/10/cisa-adds-exploited-cisco-catalyst-sd.html

## Ferramentas

| Ferramenta | Uso |
| --- | --- |
| `semgrep` (`p/owasp-top-ten`, `p/django`, `p/nextjs`, `p/secrets`) | SAST por padrão |
| `bandit` | SAST Python |
| `pip-audit`, `npm audit`, `osv-scanner`, `trivy` | dependências e imagens |
| `gitleaks`, `trufflehog` | segredos no código e no histórico |
| `nuclei` (templates oficiais) | checagem dinâmica de exposição/CVE — só alvo autorizado |
| OWASP ZAP baseline (`zap-baseline.py`) | varredura passiva de headers/cookies |
| Burp Suite + Autorize | IDOR/BFLA com duas sessões |
| `testssl.sh` | TLS |
| `sqlmap` | SQLi — só com autorização explícita, em homologação |
