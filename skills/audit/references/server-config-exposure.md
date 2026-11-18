# Configuração de servidor e exposição de dados (OWASP A02, A04, A09, A10:2025)

## Headers de resposta

| Header | Valor recomendado |
| --- | --- |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (+ `preload` quando seguro) |
| `Content-Security-Policy` | sem `unsafe-inline`/`unsafe-eval` em `script-src`; `frame-ancestors 'self'`; `object-src 'none'`; `base-uri 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` ou mais estrito |
| `Permissions-Policy` | negar o que não usa (`camera=(), microphone=(), geolocation=()`) |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `X-Frame-Options` | `DENY`/`SAMEORIGIN` (legado; `frame-ancestors` cobre) |
| Remover | `Server` com versão, `X-Powered-By`, `X-AspNet-Version`, `X-Debug-*` |

Verificar com `scripts/check_headers.sh`, Mozilla Observatory ou securityheaders.com (este último só em alvo público do próprio usuário).

## TLS

- [ ] TLS 1.2+ (1.3 preferido); sem SSLv3/TLS 1.0/1.1; sem cifras RC4/3DES/CBC-SHA1 legadas.
- [ ] Redirect HTTP → HTTPS; certificado válido e renovação automática.
- [ ] `testssl.sh <host>` ou SSL Labs para auditoria.

## Framework em modo produção

| Stack | Checar |
| --- | --- |
| Django | `DEBUG=False`; `SECRET_KEY` fora do código e forte; `ALLOWED_HOSTS` explícito; `SECURE_PROXY_SSL_HEADER` só atrás de proxy que sobrescreve o header; `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`; `python manage.py check --deploy` sem alertas relevantes; admin em URL não óbvia + 2FA |
| Flask/Werkzeug | `debug=False` (debugger = RCE; **Werkzeug CVE-2024-34069**); `SECRET_KEY` forte |
| Node/Express | `NODE_ENV=production`; `helmet`; sem stack trace na resposta; `x-powered-by` desligado |
| Next.js | `productionBrowserSourceMaps` desligado; variáveis `NEXT_PUBLIC_*` sem segredo; header `x-middleware-subrequest` removido na borda |
| Spring Boot | Actuator: expor só `health`/`info`; `/actuator/heapdump` e `/env` vazam segredos |
| Laravel | `APP_DEBUG=false` (Ignition em debug já deu RCE, CVE-2021-3129); `APP_KEY` secreta (vazada = desserialização → RCE) |
| PHP | `display_errors=Off`, `expose_php=Off`; **PHP CVE-2026-109618 / CVE-2026-109619 ("php2shell")**, RCE sem auth, KEV em out/2026: atualizar para 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 |

## Exposição de arquivos e caminhos

Caminhos que não podem responder 200 em produção:

```text
/.git/HEAD  /.git/config  /.env  /.env.local  /.env.production  /.DS_Store
/config.json  /docker-compose.yml  /Dockerfile  /.aws/credentials  /id_rsa
/backup.zip  /db.sql  /dump.sql  /*.bak  /*.old  /*~
/phpinfo.php  /server-status  /server-info
/actuator  /actuator/env  /actuator/heapdump  /__debug__/  /debug/pprof/
/swagger-ui.html  /swagger/  /openapi.json  /api-docs  /graphql (introspecção)
/static/*.js.map  /_next/static/**/*.map
/admin/ sem proteção adicional  /flower/  /metrics  /grafana/  /kibana/
```

Também: listagem de diretório ligada, bucket S3/GCS público, snapshots/backups de banco públicos, painel de fila (Flower, RabbitMQ management, Redis Commander) aberto.

## Serviços de infraestrutura

- [ ] Banco, Redis, RabbitMQ, Elasticsearch, Memcached, Mongo **sem porta pública** (bind em rede interna/127.0.0.1, firewall), com senha/ACL. Redis exposto é invadido em horas (escrita de chave SSH, cron, módulos). **Redis CVE-2025-49844 ("RediShell")**, CVSS 10: use-after-free no Lua → RCE para usuário autenticado; atualizar e desabilitar `EVAL` para usuários de app via ACL.
- [ ] Docker: `docker.sock` não montado em container exposto; portas publicadas só as necessárias (`127.0.0.1:5432:5432`, não `5432:5432` — o Docker fura o UFW).
- [ ] Proxy reverso atualizado: **Traefik CVE-2025-32431** (path traversal contorna regra), **Ingress-NGINX CVE-2025-1974 "IngressNightmare"** (RCE sem auth via webhook de admissão), **Apache Tomcat CVE-2025-24813** (PUT parcial → RCE, KEV).
- [ ] SSH: só chave, sem root, versão corrigida (**regreSSHion CVE-2024-6387**).
- [ ] Painéis de proxy (Traefik dashboard, Portainer) atrás de auth forte e fora da internet.

## Exposição de dados e criptografia (A04)

- [ ] Segredos fora do repositório (`gitleaks`, `trufflehog` no histórico também — commit removido continua no git).
- [ ] Bundle JS sem chave de serviço (`service_role`, `sk_live_`, `AKIA`, token de API privado).
- [ ] Dados pessoais/sensíveis (CPF, saúde, cartão) cifrados em repouso quando a regra exige; mascarados em tela, log e exportação. LGPD: minimização e base legal.
- [ ] Logs sem senha, token, OTP, cookie, cartão, documento completo.
- [ ] Backups cifrados e com acesso restrito.
- [ ] Respostas de API sem campos internos (hash, tokens, flags de admin, dados de outros usuários em objetos aninhados).
- [ ] Cache: respostas autenticadas com `Cache-Control: private, no-store`; CDN não cacheia página com dado de usuário (**Next.js CVE-2025-57752**, confusão de chave de cache na otimização de imagem; *web cache deception* com `/perfil/x.css`).

## A09 — logging e alerta

- [ ] Login com falha, bloqueio, troca de senha/e-mail/2FA, mudança de permissão e acesso negado são registrados com usuário, IP e horário.
- [ ] Alerta para pico de 401/403/429, criação de admin, acesso a caminho sensível.
- [ ] Logs centralizados, com retenção e fora do alcance de quem invade o app.

## A10 — tratamento de condições excepcionais (novo em 2025)

- [ ] Falha ao checar permissão/assinatura/licença **nega** (fail closed); `except: pass` em volta de checagem de segurança é achado.
- [ ] Timeout de serviço de autorização não libera acesso.
- [ ] Exceção não deixa transação pela metade (saldo debitado sem pedido criado).
- [ ] Erro não expõe stack trace, SQL, caminho ou versão.

Busca útil: `except Exception: pass`, `except: pass`, `catch (e) {}`, `catch (Exception e) { }`, `return True` dentro de `except`.
