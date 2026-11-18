# CVEs e incidentes de referência (2024 → nov/2026)

Use para cruzar com as versões do projeto. **Esta lista envelhece**: antes de afirmar que uma versão está segura, confirmar no advisory oficial ou rodar `osv-scanner` / `pip-audit` / `npm audit`. Itens de 2026 marcados com † vieram de fontes secundárias na pesquisa — conferir no advisory do mantenedor antes de citar versão corrigida.

Como checar uma versão rapidamente:

```bash
curl -s https://api.osv.dev/v1/query -d '{"package":{"name":"django","ecosystem":"PyPI"},"version":"5.2.8"}' | jq '.vulns[].id'
```

## Python

| Pacote | CVE | Tipo | Corrigido em |
| --- | --- | --- | --- |
| Django | CVE-2026-1207, CVE-2026-1287, CVE-2026-1312 | SQLi (PostGIS raster, alias de coluna em `FilteredRelation`/`annotate`, ordenação) | 6.0.2, 5.2.11, 4.2.28 |
| Django | CVE-2026-1285 | DoS em `Truncator` HTML | 6.0.2, 5.2.11, 4.2.28 |
| Django | CVE-2025-64459 | SQLi via `_connector` em `**kwargs` de `filter`/`Q` (crítica) | 5.2.8, 5.1.14, 4.2.26 |
| Django | CVE-2025-57833 | SQLi em alias de `FilteredRelation` | 5.2.6, 5.1.12, 4.2.24 |
| lxml | CVE-2026-41066 | XXE com parser padrão | 6.1.0 |
| Jinja2 | CVE-2024-56201, CVE-2025-27516 | fuga do sandbox / SSTI | 3.1.5, 3.1.6 |
| Werkzeug | CVE-2024-34069 | debugger → RCE | 3.0.3 |
| urllib3 | CVE-2025-50181 | desligar redirect não funcionava (SSRF) | 2.5.0 |
| requests | CVE-2024-35195, CVE-2024-47081 | `verify=False` persistia na sessão; vazamento de `.netrc` | 2.32.0, 2.32.4 |
| gunicorn | CVE-2024-1135, CVE-2024-6827 | HTTP request smuggling | 22.0.0, 23.0.0 |
| h11 | CVE-2025-43859 | request smuggling (afeta uvicorn/httpx) | 0.16.0 |
| python-jose | CVE-2024-33663 | confusão de algoritmo JWT | 3.4.0 (preferir PyJWT/joserfc) |
| PyJWT | CVE-2024-53861 | `iss` validado por substring | 2.10.1 |

## JavaScript / Node

| Pacote | CVE / GHSA | Tipo | Corrigido em |
| --- | --- | --- | --- |
| react-server-dom-* / Next.js | CVE-2025-55182 ("React2Shell", CVSS 10) | desserialização Flight → RCE sem auth | React 19.0.1/19.1.2/19.2.1; Next 15.x/16.x corrigidos (dez/2025) |
| Next.js | CVE-2025-55183, CVE-2025-55184, CVE-2025-67779 | vazamento de código de Server Function; DoS | follow-ups de dez/2025 |
| Next.js | lote de maio/2026: GHSA-267c-6grr-h53f, GHSA-492v-c6pp-mqqv, GHSA-26hh-7cqf-hhc6, GHSA-36qx-fr4f-26g5, GHSA-c4j6-fc7j-m34r | bypass de middleware/proxy, SSRF, cache poisoning, XSS, DoS (13 advisories) | 16.2.6 / 15.5.18 † |
| Next.js | lote de julho/2026: GHSA-p9j2-gv94-2wf4, GHSA-89xv-2m56-2m9x, GHSA-6gpp-xcg3-4w24 | SSRF em rewrites e Server Actions; bypass com Turbopack + i18n (9 advisories) | 16.2.11 / 15.5.21 † |
| Next.js | CVE-2026-96889 † | RCE em RSC/processamento de SVG (out/2026) | ver advisory da Vercel |
| Next.js | CVE-2025-29927 | `x-middleware-subrequest` pula middleware (auth) | 15.2.3, 14.2.25, 13.5.9, 12.3.5 |
| Next.js | CVE-2024-34351, CVE-2025-57822, CVE-2025-57752 | SSRF (Host, `next()` headers); confusão de cache de imagem | 14.1.1; 14.2.32/15.4.7 |
| axios | CVE-2025-27152, CVE-2025-58754 | SSRF com `baseURL`; DoS com `data:` URI | 1.8.2, 1.12.0 |
| Vite (dev server) | CVE-2025-30208, CVE-2025-31125, CVE-2025-31486 | bypass de `fs.deny` → leitura de arquivo | 6.2.x corrigidos; nunca expor dev server |
| DOMPurify | CVE-2024-45801, CVE-2024-47875, CVE-2025-26791 | bypass de sanitização (mXSS) | 3.2.4 |
| path-to-regexp | CVE-2024-45296 | ReDoS (Express) | 0.1.10 / 8.0.0 |
| xml-crypto / samlify | CVE-2025-29775, CVE-2025-29774 | bypass de assinatura SAML | xml-crypto 6.0.1 / 3.2.1 / 2.1.6 |
| mcp-remote | CVE-2025-6514 | injeção de comando via servidor MCP malicioso | 0.1.16 |

## Java / JVM

| Pacote | CVE | Tipo | Corrigido em |
| --- | --- | --- | --- |
| Apache Tomcat | CVE-2025-24813 | PUT parcial → RCE (KEV) | 11.0.3, 10.1.35, 9.0.99 |
| Spring Security | CVE-2025-41232, CVE-2025-41248 | `@PreAuthorize` ignorado (método privado / genéricos) | 6.4.6+, 6.5.4+ |
| Spring Security | CVE-2025-22228 | bcrypt aceita > 72 bytes | 6.4.4, 6.3.8 |
| Apache Tika | CVE-2025-54988, CVE-2025-66516 | XXE via XFA em PDF (crítica) | 3.2.2 / 3.2.x mais recente |
| Apache Parquet | CVE-2025-30065 | desserialização → RCE | 1.15.1 |
| http4s-scala-xml | CVE-2026-61741 † | XXE (crítica) | ver advisory |
| AssertJ | CVE-2026-24400 † | XXE em pretty-printer XML (teste/CI) | ver advisory |

## PHP / Ruby

| Pacote | CVE | Tipo | Corrigido em |
| --- | --- | --- | --- |
| PHP | CVE-2026-109618, CVE-2026-109619 ("php2shell", KEV out/2026) | RCE sem auth | 8.5.12, 8.4.27, 8.3.36, 8.2.35 |
| PHP-CGI | CVE-2024-4577 | injeção de argumento (Windows, KEV) | 8.3.8, 8.2.20, 8.1.29 |
| Livewire | CVE-2025-54068 | RCE por hidratação de propriedades | 3.6.4 |
| Craft CMS | CVE-2025-32432 | RCE sem auth (KEV) | 5.6.17 / 4.14.15 / 3.9.15 |
| ruby-saml | CVE-2024-45409, CVE-2025-25291, CVE-2025-25292 | bypass de autenticação SAML | 1.18.0 |

## Infraestrutura e borda

| Componente | CVE | Tipo | Ação |
| --- | --- | --- | --- |
| Apache httpd mod_http2 | CVE-2026-119618 † | crítica (nov/2026) | 2.4.71 |
| Redis | CVE-2025-49844 ("RediShell", CVSS 10) | UAF no Lua → RCE autenticado | 8.2.2 / 7.4.6 / 7.2.11 / 6.2.20; ACL bloqueando `EVAL` |
| Ingress-NGINX | CVE-2025-1974 ("IngressNightmare", 9.8) | RCE sem auth no admission webhook | controller 1.12.1 / 1.11.5 |
| Traefik | CVE-2025-32431 | path traversal contorna regra de middleware | 2.11.24 / 3.3.6 |
| HTTP/2 (vários) | CVE-2023-44487, CVE-2025-8671 | Rapid Reset / MadeYouReset (DoS) | atualizar proxy e servidor |
| OpenSSH | CVE-2024-6387 ("regreSSHion") | RCE sem auth | 9.8p1 |
| PostgreSQL libpq | CVE-2025-1094 | escape incorreto → SQLi no `psql` | 17.3, 16.7, 15.11, 14.16, 13.19 |
| Erlang/OTP SSH | CVE-2025-32433 (CVSS 10) | RCE sem auth | OTP-27.3.3 / 26.2.5.11 / 25.3.2.20 |

KEV de 2026 em appliances com painel web (padrão: bypass de auth em API exposta): Cisco ISE CVE-2026-76460, Cisco Catalyst SD-WAN Manager CVE-2026-76504, N-able N-central CVE-2026-18577, SimpleHelp CVE-2026-48558, PAN-OS CVE-2026-0257, Fortinet CVE-2026-24858, BeyondTrust CVE-2026-102764, Ivanti Connect Secure CVE-2026-104935.

## Cadeia de suprimentos (OWASP A03:2025)

| Quando | Incidente | Lição |
| --- | --- | --- |
| mai/2026 | **Mini Shai-Hulud** (CVE-2026-45321): worm em TanStack, Mistral AI, UiPath, OpenSearch; ~170 pacotes npm + `guardrails-ai` 0.10.1 e `mistralai` 2.4.6 no PyPI; versões maliciosas **com provenance válido** | provenance não basta; máquina que instalou = comprometida, rotacionar todos os segredos acessíveis |
| mai/2026 | conta `atool` (@antv): 639 versões maliciosas em 323 pacotes em ~1 h | atraso mínimo antes de aceitar versão nova |
| mai/2026 | **TrapDoor**: npm + PyPI + crates; pacote PyPI executa no `import` e baixa payload remoto | código no import/postinstall é vetor |
| jun–jul/2026 | `@redhat-cloud-services` (32 pacotes), variante Shai-Hulud, SDKs de pagamento typosquat, token roubado, pipeline de CI sequestrado | CI é alvo; tokens de publicação de curta duração |
| set/2025 | **Shai-Hulud** (worm npm) e **chalk/debug** (phishing de mantenedor, 18 pacotes, bilhões de downloads/semana) | 2FA resistente a phishing para mantenedores |
| mar/2025 | **tj-actions/changed-files** CVE-2025-30066 | fixar GitHub Actions por SHA, não por tag |
| ago/2025 | **Nx "s1ngularity"**: pacote malicioso usando CLIs de IA locais para achar segredos | agentes de IA locais ampliam o alcance do malware |

### Checklist de supply chain

- [ ] Lockfile commitado e instalação reprodutível (`npm ci`, `pip install --require-hashes`, `uv sync --frozen`, `poetry install --sync`).
- [ ] Atraso mínimo para versões novas (pnpm `minimumReleaseAge`, Renovate `minimumReleaseAge: "3 days"`, npm `--before`).
- [ ] Scripts de instalação desligados onde possível (`npm config set ignore-scripts true`; pnpm `onlyBuiltDependencies`).
- [ ] GitHub Actions fixadas por SHA; `permissions:` mínimas; sem `pull_request_target` executando código do PR.
- [ ] Tokens de publicação via Trusted Publishing (OIDC), não token de longa duração.
- [ ] `osv-scanner`/Dependabot/Renovate rodando no CI; imagem base atualizada (`trivy image`).
- [ ] SBOM gerado (`syft`, `cyclonedx`) para responder rápido "estamos afetados?".
