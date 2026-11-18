# web-security-audit

Skill de auditoria de segurança para sistemas web, de qualquer stack: Django, Flask/FastAPI, Node/Express/Next.js, Spring, Laravel/PHP, Rails, Supabase.

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

Segue o formato aberto [Agent Skills](https://agentskills.io): funciona no Claude Code, no Codex da OpenAI e em outros agentes que leem `SKILL.md`. Os scripts também rodam sem IA.

## Conteúdo

```text
skills/audit/
├── SKILL.md                 roteiro da auditoria e formato do relatório
├── references/              checklist por tema + catálogo de CVEs + fontes
└── scripts/
    ├── scan_code.sh         busca padrões perigosos no código
    └── check_headers.sh     checagem só de leitura de um site no ar
```

## Claude Code

Instalar:

```text
/plugin marketplace add gitsagat/web-security-audit
/plugin install web-security-audit@security-tools
```

Usar, com o Claude Code aberto na pasta do projeto:

```text
/web-security-audit:audit dependências contra CVEs
/web-security-audit:audit IDOR nas rotas da API
/web-security-audit:audit login e 2FA
```

Atualizar: `/plugin marketplace update security-tools`.

## Codex (OpenAI)

Instalar:

```bash
git clone https://github.com/gitsagat/web-security-audit.git ~/web-security-audit
mkdir -p ~/.codex/skills
cp -r ~/web-security-audit/skills/audit ~/.codex/skills/web-security-audit
```

Usar, com o Codex aberto na pasta do projeto:

```text
$audit dependências contra CVEs
$audit IDOR nas rotas da API
```

Atualizar: `cd ~/web-security-audit && git pull`, depois repetir o `cp -r`.

## Outros agentes

Cursor, GitHub Copilot, Gemini CLI e outros leem o mesmo formato. Copie `skills/audit` para a pasta de skills do agente (veja a documentação dele) e peça em texto: "usa a skill web-security-audit para revisar o login".

## Chat (ChatGPT, Claude.ai)

Anexe `skills/audit/SKILL.md`, a referência do tema (por exemplo `references/authz-rls-idor.md`) e o código a revisar. Peça: "Siga o SKILL.md e a referência para auditar este código."

## Sem IA

```bash
git clone https://github.com/gitsagat/web-security-audit.git ~/web-security-audit
bash ~/web-security-audit/skills/audit/scripts/scan_code.sh .
bash ~/web-security-audit/skills/audit/scripts/check_headers.sh https://site-autorizado
```

Rode o `scan_code.sh` de dentro da pasta do projeto. Ele lista candidatos, não vulnerabilidades: cada linha precisa ser conferida. O `check_headers.sh` só lê, mas use só em site que você pode testar. `INSECURE=1` antes do comando aceita certificado autoassinado.

Os scripts são bash: Linux, macOS, WSL ou Git Bash. No Windows, use o WSL.

## Regras

- Audite por partes (dependências, IDOR, login, webhooks, injeções, configuração). Pedir "tudo" de uma vez gera relatório raso.
- Teste em site no ar só com autorização. Nada destrutivo.
- Relatório de auditoria fica na sua máquina, fora do git: crie uma pasta no projeto e ponha no `.gitignore`.

## Manutenção

- `references/cves.md` envelhece: atualize a partir de `references/sources.md`.
- Suba `version` em `.claude-plugin/plugin.json` a cada mudança na skill.

## Licença

MIT — veja [LICENSE](LICENSE).
