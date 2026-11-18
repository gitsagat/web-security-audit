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

A instalação tem dois caminhos. Os comandos são parecidos, mas são digitados em lugares diferentes:

| Onde você digita | Comando começa com | Exemplo |
| --- | --- | --- |
| Na caixa de mensagem do Claude Code (terminal ou VS Code) | `/plugin` | `/plugin install ...` |
| No terminal do sistema (bash, zsh, WSL) | `claude plugin` | `claude plugin install ...` |

Comando com `/` no começo **não funciona no bash**, e `claude plugin` **não funciona na caixa de mensagem**.

### Caminho 1: dentro do Claude Code

Na caixa de mensagem do Claude Code, um comando por vez:

```text
/plugin marketplace add gitsagat/web-security-audit
/plugin install web-security-audit@security-tools
```

Se aparecer `/plugin isn't available in this environment`, a sua versão (comum na extensão do VS Code) não tem esse comando. Use o caminho 2.

### Caminho 2: pelo terminal

No terminal do sistema (no Windows, o terminal do WSL):

```bash
claude plugin marketplace add gitsagat/web-security-audit
claude plugin install web-security-audit@security-tools
claude plugin list
```

O último comando deve mostrar `web-security-audit@security-tools` com `Status: ✔ enabled`. Se aparecer `claude: command not found`, veja [Problemas comuns](#problemas-comuns).

### Usar

Depois de instalar, **abra uma conversa nova** no Claude Code (a conversa que já estava aberta não enxerga o plugin). Com o Claude Code aberto na pasta do projeto, digite na caixa de mensagem `/web-security-audit:audit` seguido do que quer auditar.

Audite por partes: um tema por vez gera um relatório mais fundo do que pedir tudo de uma vez.

#### Visão geral

```text
/web-security-audit:audit reconhecimento: stack, rotas, áreas públicas e modelo de permissões
/web-security-audit:audit varredura automática do código com o scan_code.sh
/web-security-audit:audit auditoria completa, priorizando os riscos mais graves
```

#### Dependências e cadeia de suprimentos

```text
/web-security-audit:audit dependências contra CVEs
/web-security-audit:audit lockfile, scripts de instalação e GitHub Actions
/web-security-audit:audit segredos no código e no histórico do git
```

#### Permissões, IDOR e RLS

```text
/web-security-audit:audit IDOR nas rotas da API
/web-security-audit:audit isolamento entre clientes (multi-tenant)
/web-security-audit:audit mass assignment nos serializers e formulários
/web-security-audit:audit funções de admin acessíveis por usuário comum
/web-security-audit:audit políticas RLS do Supabase/PostgreSQL
/web-security-audit:audit acesso a arquivos e mídia privada
```

#### Autenticação e 2FA

```text
/web-security-audit:audit login e 2FA
/web-security-audit:audit recuperação de senha e troca de e-mail
/web-security-audit:audit sessão, cookies e logout
/web-security-audit:audit JWT e tokens de API
/web-security-audit:audit SSO com SAML ou OIDC
```

#### Injeções

```text
/web-security-audit:audit SQL injection
/web-security-audit:audit XSS nos templates e no front-end
/web-security-audit:audit XXE nos parsers de XML e documentos
/web-security-audit:audit injeção de comando, de template e desserialização
/web-security-audit:audit path traversal em upload e download
```

#### Requisições e APIs

```text
/web-security-audit:audit CSRF e CORS
/web-security-audit:audit SSRF em webhooks, importação por URL e geração de PDF
/web-security-audit:audit assinatura dos webhooks recebidos
/web-security-audit:audit rate limit em login, OTP e envio de mensagens
/web-security-audit:audit condição de corrida em pagamento, cupom e estoque
/web-security-audit:audit documentação e rotas de debug expostas
```

#### Configuração e exposição de dados

```text
/web-security-audit:audit configuração de produção do framework
/web-security-audit:audit portas e serviços expostos no docker-compose
/web-security-audit:audit dados pessoais em logs, respostas e exportações
/web-security-audit:audit tratamento de erros que libera acesso
```

#### Teste no ar (só em site que você pode testar)

```text
/web-security-audit:audit headers, cookies e TLS em https://<seu-site>
/web-security-audit:audit caminhos expostos (.git, .env, swagger) em https://<seu-site>
/web-security-audit:audit IDOR com duas contas de teste em https://<seu-site>
```

#### Recorte específico

```text
/web-security-audit:audit o arquivo <caminho/do/arquivo>
/web-security-audit:audit a pasta <caminho/da/pasta>
/web-security-audit:audit as mudanças ainda não commitadas
/web-security-audit:audit as mudanças desta branch em relação à main
```

#### Depois da auditoria

Na mesma conversa, sem o prefixo:

```text
salva o relatório em docs/security-audit/<nome>.md
corrige o achado 1 e escreve um teste que prove a correção
explica o achado 3 com um exemplo de ataque
monta um plano de correção por prioridade
```

### Atualizar

Na caixa de mensagem: `/plugin marketplace update security-tools`. Pelo terminal: `claude plugin marketplace update security-tools`.

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

## Problemas comuns

| Mensagem | O que aconteceu | Como resolver |
| --- | --- | --- |
| `/plugin isn't available in this environment` | A sua versão do Claude Code (em geral a extensão do VS Code) não tem o comando `/plugin` | Instalar pelo terminal: [caminho 2](#caminho-2-pelo-terminal) |
| `-bash: /plugin: No such file or directory` | Um comando do Claude Code foi digitado no bash | No terminal, use `claude plugin ...` em vez de `/plugin ...` |
| `claude: command not found` | O CLI do Claude Code não está instalado no terminal; a extensão do VS Code não instala esse comando | Ver abaixo |
| `/web-security-audit:audit` não aparece | A conversa foi aberta antes da instalação | Abrir uma conversa nova; conferir com `claude plugin list` |
| A skill aparece duas vezes | Há uma cópia manual antiga em `~/.claude/skills/` | Apagar a cópia manual e ficar só com o plugin |

### `claude: command not found`

Escolha uma das opções.

Instalar o CLI oficial:

```bash
curl -fsSL https://claude.ai/install.sh | bash
```

Ou, se você já usa a extensão do VS Code no WSL ou num servidor remoto, usar o executável que vem dentro dela:

```bash
echo 'alias claude="$(ls -d ~/.vscode-server/extensions/anthropic.claude-code-*/resources/native-binary/claude | sort -V | tail -1)"' >> ~/.bashrc
source ~/.bashrc
claude --version
```

Com o VS Code instalado direto no Linux ou no macOS (sem WSL), a pasta é `~/.vscode/extensions/` em vez de `~/.vscode-server/extensions/`.

## Regras

- Audite por partes (dependências, IDOR, login, webhooks, injeções, configuração). Pedir "tudo" de uma vez gera relatório raso.
- Teste em site no ar só com autorização. Nada destrutivo.
- Relatório de auditoria fica na sua máquina, fora do git: crie uma pasta no projeto e ponha no `.gitignore`.

## Manutenção

- `references/cves.md` envelhece: atualize a partir de `references/sources.md`.
- Suba `version` em `.claude-plugin/plugin.json` a cada mudança na skill.

## Licença

MIT — veja [LICENSE](LICENSE).
