# web-security-audit

Plugin do Claude Code com uma skill de auditoria de segurança para sistemas web, de qualquer stack: Django, Flask/FastAPI, Node/Express/Next.js, Spring, Laravel/PHP, Rails, Supabase.

Cobre:

- XSS, CSRF e SSRF
- SQL Injection, XXE e outras injeções
- Autenticação, sessão e 2FA
- Permissões, políticas RLS e multi-tenant
- Acesso indevido a objetos (IDOR/BOLA)
- Rate limit e segurança de APIs
- Configuração de servidor e exposição de dados
- Dependências, cadeia de suprimentos e CVEs recentes

Base: OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP ASVS 5.0, CWE Top 25, catálogo KEV da CISA.

## Conteúdo

```text
skills/audit/
├── SKILL.md                         roteiro da auditoria e formato do relatório
├── references/
│   ├── xss-csrf-ssrf.md
│   ├── injection-sqli-xxe.md
│   ├── auth-2fa.md
│   ├── authz-rls-idor.md
│   ├── rate-limit-api.md
│   ├── server-config-exposure.md
│   ├── cves.md                      catálogo de CVEs e incidentes de supply chain
│   └── sources.md                   fontes primárias e ferramentas
└── scripts/
    ├── scan_code.sh                 busca padrões perigosos no código
    └── check_headers.sh             checagem só de leitura de um alvo no ar
```

## Instalação

Este repositório é ao mesmo tempo o marketplace (`security-tools`) e o plugin (`web-security-audit`).

### Para você, em qualquer projeto

Dentro do Claude Code:

```text
/plugin marketplace add gitsagat/web-security-audit
/plugin install web-security-audit@security-tools
```

### Em um projeto, para todo o time

No `.claude/settings.json` versionado do projeto:

```json
{
  "extraKnownMarketplaces": {
    "security-tools": {
      "source": { "source": "github", "repo": "gitsagat/web-security-audit" }
    }
  },
  "enabledPlugins": {
    "web-security-audit@security-tools": true
  }
}
```

Cada pessoa, uma vez por clone:

```bash
claude plugin install web-security-audit@security-tools --scope project
```

### Teste local, sem GitHub

```bash
claude plugin validate . --strict
claude plugin marketplace add /caminho/para/web-security-audit
claude plugin install web-security-audit@security-tools
```

Ou só para uma sessão: `claude --plugin-dir /caminho/para/web-security-audit`.

## Uso com o Claude Code

O comando é `/web-security-audit:audit`. Também dá para pedir em linguagem natural no projeto:

- "audita a segurança deste sistema"
- "procura IDOR nas views de API"
- "confere as políticas RLS do Supabase"
- "cruza as dependências com CVEs recentes"

A skill também é acionada sozinha quando a conversa fala de XSS, CSRF, SSRF, SQL injection, XXE, 2FA, RLS, IDOR, rate limit, headers de segurança ou exposição de dados.

## Uso sem o Claude Code

Os scripts rodam sozinhos, em qualquer projeto:

```bash
bash skills/audit/scripts/scan_code.sh /caminho/do/projeto
bash skills/audit/scripts/check_headers.sh https://alvo-autorizado
INSECURE=1 bash skills/audit/scripts/check_headers.sh https://dev.local
```

`scan_code.sh` lista candidatos, não vulnerabilidades: cada linha precisa ser confirmada lendo o fluxo de dados. `check_headers.sh` só faz requisições de leitura, mas só deve ser apontado para sistemas que você tem autorização para testar.

## Regras

- Teste dinâmico só contra alvo autorizado. Nada destrutivo.
- **Relatórios de auditoria não entram neste repositório.** Eles descrevem falhas reais de um sistema e ficam no projeto auditado, fora do git. O `.gitignore` já recusa `relatorios/` e `reports/`.
- A skill é genérica. Regras específicas de um sistema (modelo de tenant, papéis) ficam no `CLAUDE.md` daquele projeto.

## Manutenção

- `references/cves.md` envelhece. Ao atualizar, partir das fontes de `references/sources.md` (advisory do mantenedor, OSV, CISA KEV), não de agregadores. Item sem confirmação no advisory oficial leva a marca †.
- Subir `version` em `.claude-plugin/plugin.json` a cada mudança, para os projetos receberem a atualização.
- O workflow `self-test` valida sintaxe, ShellCheck e os JSON do plugin.

## Licença

MIT — veja [LICENSE](LICENSE). Contribuições com CVEs novas, padrões de busca e correções são bem-vindas por pull request.
