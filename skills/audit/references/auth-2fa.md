# Autenticação, sessão e 2FA (OWASP A07:2025, ASVS V6/V7)

## Onde procurar

- Fluxos: login, cadastro, recuperação de senha, troca de e-mail, troca de senha, convite, magic link, OTP por SMS/WhatsApp/e-mail, SSO (SAML/OIDC), "lembrar-me", login social, API tokens, logout.
- Código: views de login, backends de autenticação customizados, middleware que decide "está logado", geração e validação de token (JWT, reset, OTP), armazenamento de senha.

## Checklist — senha e login

- [ ] Hash com Argon2id, scrypt ou bcrypt (custo ≥ 10) / PBKDF2 com iterações atuais (Django já faz). Nunca MD5/SHA puro.
- [ ] bcrypt trunca em 72 bytes: senha longa ou concatenação `usuario+senha` vira bypass (caso **Okta out/2024**, cache de AD com username ≥ 52 caracteres; **Spring Security CVE-2025-22228**, `BCryptPasswordEncoder` aceitando senha > 72).
- [ ] Mesma mensagem e mesmo tempo para "usuário não existe" e "senha errada" (enumeração).
- [ ] Rate limit e bloqueio progressivo por conta **e** por IP (ver [rate-limit-api.md](rate-limit-api.md)).
- [ ] Senha mínima 8 (com MFA) / 15 (sem MFA) e checagem contra senhas vazadas (NIST SP 800-63B rev. 4); sem regra de composição forçada nem expiração periódica.
- [ ] Senhas padrão inexistentes em produção (**McHire/McDonald's, jul/2025**: painel com `123456:123456` + IDOR expôs 64 milhões de candidatos).

## Checklist — sessão

- [ ] ID de sessão regenerado no login e na elevação de privilégio (fixação de sessão).
- [ ] Cookie `Secure`, `HttpOnly`, `SameSite=Lax/Strict`, prefixo `__Host-` quando possível.
- [ ] Logout invalida no servidor; troca de senha encerra as outras sessões.
- [ ] Timeout ocioso e absoluto definidos.

## Checklist — tokens (JWT, reset, magic link)

- [ ] JWT: algoritmo fixado na verificação (`algorithms=["RS256"]`), `alg: none` recusado, `aud`, `iss`, `exp` validados; segredo HMAC forte; sem confusão RS/HS. Casos: **python-jose CVE-2024-33663** (confusão de algoritmo), **PyJWT CVE-2024-53861** (comparação parcial de `iss`).
- [ ] Token de reset: aleatório criptográfico (≥ 128 bits), uso único, expira em minutos, invalidado ao trocar senha, comparado em tempo constante.
- [ ] Link de reset construído com host configurado, **nunca** com `Host` do request (envenenamento de reset).
- [ ] Reset envia só para o e-mail verificado do cadastro: **GitLab CVE-2023-7028** aceitava array de e-mails e mandava o token para o do atacante (KEV).

## Checklist — 2FA/MFA

- [ ] Segundo fator checado **no servidor** antes de emitir sessão plena — não só uma tela no front que pode ser pulada indo direto para `/dashboard`.
- [ ] Estado "senha ok, falta 2FA" é uma sessão parcial que não acessa nada além da tela de OTP.
- [ ] OTP: 6+ dígitos, expira (TOTP janela ±1; SMS/e-mail ≤ 10 min), uso único, **tentativas limitadas** (6 dígitos sem limite caem em força bruta em horas).
- [ ] Código de backup com hash, uso único.
- [ ] Desativar 2FA, trocar e-mail, trocar telefone e criar token de API exigem reautenticação.
- [ ] Preferir TOTP/WebAuthn/passkeys a SMS (SIM swap). Para WhatsApp/SMS, limitar envio por número e por IP (custo e abuso).
- [ ] Resposta da etapa 1 não vaza o OTP nem o "código correto" no JSON (bug comum).
- [ ] "Lembrar este dispositivo" com token próprio, revogável, amarrado ao usuário.

## SSO (SAML / OIDC)

- [ ] SAML: biblioteca atualizada; assinatura validada sobre a asserção usada, não sobre outra parte do documento (XML signature wrapping). Casos: **ruby-saml CVE-2024-45409** e **CVE-2025-25291/25292** (diferencial entre parsers REXML/Nokogiri → bypass), **xml-crypto CVE-2025-29775/29774** e **samlify** (Node).
- [ ] OIDC: `state` e `nonce` validados, PKCE em clientes públicos, `redirect_uri` comparado exatamente (sem prefixo/curinga), `id_token` com `aud` = client_id.
- [ ] Vinculação de conta social por e-mail só se o provedor afirma `email_verified`.

## Bypass de autenticação por framework/borda

O "está logado?" decidido em middleware/proxy pode ser contornado por caminho alternativo:

- **Next.js CVE-2025-29927**: header `x-middleware-subrequest` pulava o middleware inteiro (auth incluída). Remover o header na borda; atualizar.
- **Next.js maio/2026**: GHSA-267c-6grr-h53f (rotas de prefetch de segmento), GHSA-492v-c6pp-mqqv (injeção em parâmetro de rota dinâmica), GHSA-26hh-7cqf-hhc6 (correção anterior não cobria Turbopack), GHSA-36qx-fr4f-26g5 (i18n no Pages Router). **Lição: middleware não pode ser a única camada de auth** — checar também no handler/Server Action/loader de dados.
- **Spring Security CVE-2025-41232 / CVE-2025-41248**: anotações de método (`@PreAuthorize`) ignoradas em métodos privados ou com tipos genéricos.
- **Traefik CVE-2025-32431**: `/../` no caminho contornava regra de middleware baseada em path.
- **2026 em appliances (KEV)**: Cisco ISE CVE-2026-76460, Cisco SD-WAN Manager CVE-2026-76504, N-able N-central CVE-2026-18577 (patch incompleto de CVE-2026-18556), BeyondTrust CVE-2026-102764, Ivanti Connect Secure CVE-2026-104935 — todos bypass de autenticação em API/painel. Padrão: endpoint de API exposto que confia em caminho, header ou flag em vez de checar sessão.

## Teste (alvo autorizado)

- Acessar cada rota autenticada sem cookie/token, com token expirado, com token de outro usuário, com `alg: none`.
- Pular a etapa de 2FA indo direto para uma rota interna após a etapa de senha.
- Variações de caminho: `/admin/`, `/admin`, `/Admin/`, `/admin/.`, `/./admin/`, `/admin%2f`, `/;/admin`, `//admin`.
- Reset: pedir duas vezes e testar se o primeiro token ainda vale; trocar `Host` no pedido e ver o link do e-mail.
