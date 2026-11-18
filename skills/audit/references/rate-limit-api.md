# Rate limit e segurança de APIs (OWASP API Security Top 10:2023)

| Item | Risco | Ver |
| --- | --- | --- |
| API1 | Broken Object Level Authorization (IDOR) | [authz-rls-idor.md](authz-rls-idor.md) |
| API2 | Broken Authentication | [auth-2fa.md](auth-2fa.md) |
| API3 | Broken Object Property Level Authorization (mass assignment, excesso na resposta) | [authz-rls-idor.md](authz-rls-idor.md) |
| API4 | Unrestricted Resource Consumption | abaixo |
| API5 | Broken Function Level Authorization | [authz-rls-idor.md](authz-rls-idor.md) |
| API6 | Unrestricted Access to Sensitive Business Flows | abaixo |
| API7 | SSRF | [xss-csrf-ssrf.md](xss-csrf-ssrf.md) |
| API8 | Security Misconfiguration | [server-config-exposure.md](server-config-exposure.md) |
| API9 | Improper Inventory Management | abaixo |
| API10 | Unsafe Consumption of APIs | abaixo |

## API4 — consumo de recursos sem limite

### Checklist

- [ ] Rate limit em **login, cadastro, reset de senha, envio e verificação de OTP, busca, exportação, upload, envio de mensagem/SMS/e-mail/WhatsApp** — por IP **e** por conta/identificador (número, e-mail).
- [ ] Limite com estado compartilhado (Redis) quando há mais de uma réplica; contador em memória por processo é contornável.
- [ ] IP real derivado corretamente atrás de proxy: confiar em `X-Forwarded-For` **só** a partir do proxy conhecido (Django: não ler `HTTP_X_FORWARDED_FOR` cru; Express: `trust proxy` com número de saltos exato). Senão o atacante troca o IP a cada request.
- [ ] Paginação com teto (`page_size` máximo), sem `?limit=100000`.
- [ ] Tamanho máximo de body, upload, JSON aninhado, número de campos (Django `DATA_UPLOAD_MAX_NUMBER_FIELDS`), tempo de execução de query (`statement_timeout`).
- [ ] GraphQL: limite de profundidade, complexidade e de aliases/batching (força bruta de OTP via 1.000 aliases num só request).
- [ ] Regex sobre entrada do usuário sem backtracking catastrófico (ReDoS — **path-to-regexp CVE-2024-45296**, Express).
- [ ] Borda: limite de conexões e requisições por IP no proxy (Traefik `rateLimit`/`inFlightReq`, Nginx `limit_req`), além do app.
- [ ] HTTP/2: servidor e proxy corrigidos contra **Rapid Reset CVE-2023-44487** e **MadeYouReset CVE-2025-8671**; **Apache httpd mod_http2 CVE-2026-119618** (crítica, corrigida em 2.4.71, nov/2026).
- [ ] Resposta `429` com `Retry-After`; sem revelar se o usuário existe.

Ferramentas: `django-ratelimit`, DRF `throttle_classes`, `express-rate-limit` + `rate-limit-redis`, `slowapi` (FastAPI), Bucket4j (Spring), `rack-attack` (Rails), `RateLimiter` (Laravel).

### Teste (alvo autorizado, volume baixo)

20–30 tentativas de login erradas seguidas para a mesma conta: deve bloquear ou atrasar. Repetir variando `X-Forwarded-For`: o limite deve continuar valendo. Não fazer teste de carga em produção.

## API6 — fluxos de negócio sensíveis

Fluxos que causam prejuízo mesmo sem bug técnico quando automatizados: compra de estoque limitado, cupom, cadastro em massa, disparo de SMS/WhatsApp pago (SMS pumping), votação, convites, criação de cobrança.

- [ ] Limite por conta + por dispositivo/número + custo diário.
- [ ] CAPTCHA/prova de trabalho em cadastro e envio de OTP para número arbitrário.
- [ ] Idempotência em pagamento (chave de idempotência; webhook processado uma vez).
- [ ] Condição de corrida: saldo, cupom e estoque com `SELECT ... FOR UPDATE` ou `UPDATE ... WHERE saldo >= x` atômico. Testar com 20 requisições paralelas.

## API9 — inventário

- [ ] Lista das APIs expostas e versões; `v1` antiga desligada ou com os mesmos controles da `v2`.
- [ ] Ambientes de homologação/dev não expostos publicamente ou com auth; não usam dados reais sem anonimização.
- [ ] Documentação (`/swagger`, `/openapi.json`, `/graphql` introspecção, `/redoc`) fechada em produção ou atrás de login.
- [ ] Rotas de debug, health detalhado e métricas (`/metrics`, `/actuator`, `/__debug__/`, `/flower`) fora da internet.

## API10 — consumo inseguro de APIs de terceiros

- [ ] Webhooks recebidos validam assinatura (HMAC com segredo, comparação em tempo constante, janela de timestamp contra replay). Ex.: Meta/WhatsApp `X-Hub-Signature-256`, Stripe `Stripe-Signature`, gateways de pagamento.
- [ ] Dados de terceiros validados por schema antes de gravar/renderizar (são entrada não confiável).
- [ ] Timeouts em toda chamada externa; TLS verificado (`verify=True`; procurar `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify`).
- [ ] Redirecionamentos de API externa não seguidos cegamente (SSRF).

## Segurança de API em geral

- [ ] Autenticação por token no header `Authorization`, não em query string (vaza em log e Referer).
- [ ] Tokens de API com escopo, expiração e revogação; armazenados com hash.
- [ ] CORS com lista de origens explícita.
- [ ] Mensagens de erro sem stack trace, SQL ou caminhos internos.
- [ ] Logs de auditoria de ações sensíveis (quem, o quê, quando, de onde) sem senha/token/dado de cartão.
