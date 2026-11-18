---
name: audit
description: Auditoria de segurança de sistemas web (qualquer stack — Django, Flask/FastAPI, Node/Express/Next.js, Spring, Laravel/PHP, Rails, Supabase). Use quando o usuário pedir para validar segurança, caçar vulnerabilidades, revisar código antes de produção, fazer checklist OWASP, checar CVEs de dependências, ou mencionar XSS, CSRF, SSRF, SQL injection, XXE, autenticação, 2FA, permissões, RLS, IDOR, rate limit, segurança de API, headers, configuração de servidor ou exposição de dados.
---

# Auditoria de segurança web

Roteiro para encontrar vulnerabilidades em um sistema web, por revisão de código e, quando autorizado, por teste dinâmico contra um ambiente do próprio usuário. Baseado em OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP ASVS 5.0, CWE Top 25 e no catálogo KEV da CISA.

## Regras de engajamento (sempre)

1. **Teste dinâmico só em alvo autorizado**: ambiente local, homologação ou produção do próprio usuário com autorização explícita. Nunca disparar payload contra domínio de terceiros.
2. **Não destrutivo**: nada de `DROP`, `DELETE` em massa, flood, negação de serviço ou exploração que altere dado real. Provar a falha com o mínimo (um `SLEEP(2)`, um `alert(document.domain)`, uma leitura de registro de teste).
3. **Segredos achados não saem da máquina**: reportar caminho e tipo (`AWS key em .env.example:3`), mascarando o valor.
4. Revisão de código e varredura de dependências rodam sem pedir; o teste dinâmico pede confirmação do alvo antes.

## Fluxo

### 1. Reconhecimento (5 min)

- Identificar stack, frameworks e versões: `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `package.json`, lockfiles, `pom.xml`, `build.gradle`, `composer.json`, `Gemfile.lock`, `Dockerfile`, `docker-compose*.yml`, configs de proxy (Nginx, Traefik, Caddy).
- Mapear superfície: rotas/URLs, views de API, webhooks, uploads, endpoints públicos sem login, painéis administrativos, jobs assíncronos que consomem entrada externa.
- Mapear modelo de autorização: papéis, tenant/filial/organização, como o "dono" de um registro é determinado.

### 2. Varredura automática

Os scripts ficam em `scripts/`, na mesma pasta deste `SKILL.md`. No Claude Code, `${CLAUDE_SKILL_DIR}` já vira esse caminho. Em outros agentes (Codex, Cursor, Copilot, Gemini CLI), troque `${CLAUDE_SKILL_DIR}` pelo caminho da pasta onde este arquivo está, por exemplo `~/.codex/skills/web-security-audit`.

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/scan_code.sh <raiz-do-projeto>
```

Gera candidatos por padrão perigoso (SQL cru, `|safe`, `innerHTML`, `verify=False`, parser XML sem endurecimento, `DEBUG=True`, segredos). **Cada achado é candidato, não vulnerabilidade**: confirmar lendo o fluxo de dados (a entrada chega lá controlada pelo usuário?).

Dependências (rodar o que existir na stack):

```bash
pip-audit -r requirements.txt            # Python (ou: pip-audit no venv)
npm audit --omit=dev                     # Node (ou pnpm audit / yarn npm audit)
osv-scanner scan source -r .             # multi-ecossistema, base OSV
trivy fs --scanners vuln,secret,misconfig .
gitleaks detect --no-git -s .            # segredos no working tree
semgrep scan --config p/owasp-top-ten --config p/secrets
```

Se a ferramenta não estiver instalada, dizer isso e seguir com a revisão manual — não travar.

Cruzar as versões encontradas com [references/cves.md](references/cves.md).

### 3. Revisão manual por tema

Para cada tema, abrir a referência, aplicar o checklist e os padrões de busca à stack do projeto:

| Tema | Referência | OWASP 2025 |
| --- | --- | --- |
| XSS, CSRF, SSRF | [references/xss-csrf-ssrf.md](references/xss-csrf-ssrf.md) | A05, A01 |
| SQL Injection, XXE, injeções em geral | [references/injection-sqli-xxe.md](references/injection-sqli-xxe.md) | A05 |
| Autenticação, sessão, 2FA, recuperação de senha | [references/auth-2fa.md](references/auth-2fa.md) | A07, A04 |
| Permissões, RLS, IDOR, multi-tenant | [references/authz-rls-idor.md](references/authz-rls-idor.md) | A01 |
| Rate limit e segurança de APIs | [references/rate-limit-api.md](references/rate-limit-api.md) | API Top 10 |
| Configuração de servidor e exposição de dados | [references/server-config-exposure.md](references/server-config-exposure.md) | A02, A09, A10 |
| Dependências, cadeia de suprimentos, CVEs | [references/cves.md](references/cves.md) | A03, A08 |

Fontes primárias e onde atualizar: [references/sources.md](references/sources.md).

Prioridade quando o tempo é curto: **autorização (IDOR/RLS) → autenticação → injeção → SSRF → exposição/config → resto**. Controle de acesso quebrado é a categoria nº 1 do OWASP desde 2021 e é a que scanner automático menos acha.

### 4. Teste dinâmico (só com alvo confirmado)

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/check_headers.sh https://alvo-autorizado
INSECURE=1 bash ${CLAUDE_SKILL_DIR}/scripts/check_headers.sh https://dev.local   # certificado autoassinado
```

Checa headers de segurança, cookies, TLS, métodos HTTP e caminhos que não deveriam estar expostos (`/.git/`, `/.env`, `/actuator`, source maps). Testes de IDOR exigem **duas contas de teste** em tenants/donos diferentes — pedir ao usuário.

### 5. Relatório

Um achado por bloco, ordenados por severidade:

```text
[ALTA] IDOR em GET /api/invoices/<id>/
  Onde: app/invoices/views.py:88 (InvoiceDetailView.get_queryset)
  Evidência: queryset = Invoice.objects.all(); sem filtro por tenant.
  Reprodução: conta A (tenant 1) lê /api/invoices/912/ que pertence ao tenant 2 → 200 com dados.
  Impacto: qualquer cliente lê faturas de qualquer outro.
  Correção: filtrar por request.user.tenant no get_queryset; teste com duas contas.
  Referências: CWE-639, OWASP A01:2025, API1:2023, ASVS V8
```

Severidade: **Crítica** (RCE, bypass de auth sem login, vazamento em massa), **Alta** (IDOR com dado pessoal, SQLi autenticada, SSRF a metadados de nuvem, XSS armazenada em área admin), **Média** (XSS refletida, CSRF em ação relevante, falta de rate limit em login), **Baixa** (header ausente, versão exposta), **Info**.

Fechar com: o que foi coberto, o que **não** foi coberto (e por quê), e as ferramentas que não estavam disponíveis. Não declarar "sistema seguro" — declarar o escopo verificado.
