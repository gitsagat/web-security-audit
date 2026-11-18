# XSS, CSRF e SSRF

## XSS — Cross-Site Scripting (CWE-79, OWASP A05:2025)

Entrada do usuário renderizada como HTML/JS sem escape no contexto certo. Tipos: refletida, armazenada, DOM-based, mutation XSS (mXSS, quando o sanitizador e o navegador interpretam o HTML de formas diferentes).

### Onde procurar no código

| Stack | Padrão perigoso |
| --- | --- |
| Django | `\|safe`, `mark_safe(`, `{% autoescape off %}`, `format_html` com string já interpolada (`format_html(f"...")`), `SafeString(` |
| Jinja2/Flask | `\|safe`, `Markup(`, `autoescape=False`, `render_template_string(` com entrada do usuário (vira SSTI) |
| React/Next | `dangerouslySetInnerHTML`, `href={userInput}` (aceita `javascript:`), `ref.current.innerHTML` |
| Vue | `v-html` |
| Angular | `bypassSecurityTrust*` |
| JS puro | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`, `new Function(`, `setTimeout("string")`, `$(...).html(` |
| Laravel/Blade | `{!! $var !!}` |
| Rails | `.html_safe`, `raw(` |
| Templates de e-mail, PDF e exportação | mesmo cuidado: HTML gerado para PDF (wkhtmltopdf, WeasyPrint, Puppeteer) vira SSRF/leitura de arquivo |

Contextos que o autoescape **não** cobre: atributo sem aspas, dentro de `<script>`, dentro de `style`, URL (`href`, `src`). Para JSON dentro de `<script>`, usar `json_script` (Django) ou serialização com escape de `<`, `>` e `&`.

### Checklist

- [ ] Autoescape ligado em todos os engines de template; cada `safe`/`mark_safe` tem justificativa e a entrada é confiável ou sanitizada.
- [ ] HTML rico do usuário passa por sanitizador mantido (DOMPurify ≥ 3.2.4, `nh3`/`bleach` no Python, `sanitize-html` no Node) com lista de permitidos — nunca regex.
- [ ] URLs vindas do usuário validadas por esquema (`http`, `https`, `mailto`) antes de ir para `href`/`src`.
- [ ] Content-Security-Policy sem `unsafe-inline`/`unsafe-eval` em script-src, idealmente com nonce ou hash e `strict-dynamic`; `object-src 'none'`; `base-uri 'none'`.
- [ ] Cookies de sessão com `HttpOnly`.
- [ ] Upload de SVG/HTML servido de outro domínio ou com `Content-Disposition: attachment` e `X-Content-Type-Options: nosniff`.

### Teste dinâmico (alvo autorizado)

Payloads mínimos, um de cada vez, em cada campo refletido ou armazenado:

```text
"><svg onload=alert(document.domain)>
'-alert(document.domain)-'
javascript:alert(document.domain)
<img src=x onerror=alert(document.domain)>
{{7*7}}   ${7*7}   <%= 7*7 %>     (SSTI: se aparecer 49, é injeção de template — mais grave que XSS)
```

### Casos reais

- **Grafana CVE-2025-4123** ("Grafana Ghost"): open redirect + path traversal no plugin frontend levando a XSS e SSRF.
- **DOMPurify CVE-2024-45801, CVE-2024-47875, CVE-2025-26791**: bypasses por mXSS e nesting; manter ≥ 3.2.4.
- **Roundcube CVE-2024-42009**: XSS armazenada em e-mail lido; explorada contra governos.
- **Next.js (lote de maio/2026)**: incluiu advisories de XSS junto com bypass de middleware — ver [cves.md](cves.md).

---

## CSRF — Cross-Site Request Forgery (CWE-352)

Site terceiro faz o navegador da vítima enviar requisição autenticada (cookie vai junto).

### Onde procurar

| Stack | Padrão perigoso |
| --- | --- |
| Django | `@csrf_exempt`, `CsrfViewMiddleware` ausente, `CSRF_TRUSTED_ORIGINS` com curinga amplo, view que muda estado em `GET` |
| Flask | ausência de `flask-wtf`/`CSRFProtect` em app com sessão por cookie |
| Express | sem token nem checagem de `Origin`; `csurf` (descontinuado) — preferir `csrf-csrf` ou checagem de origem |
| Spring | `csrf().disable()` / `csrf(AbstractHttpConfigurer::disable)` em app com sessão |
| Laravel | rotas em `$except` do `VerifyCsrfToken` |
| Next.js Server Actions | têm checagem de `Origin` embutida; ela falha atrás de proxy que reescreve `Host` sem `serverActions.allowedOrigins` |

### Checklist

- [ ] Toda ação que muda estado usa `POST/PUT/PATCH/DELETE`; nenhum `GET` altera dado.
- [ ] Token CSRF (sincronizado ou double-submit assinado) **ou** checagem estrita de `Origin`/`Sec-Fetch-Site` nas rotas com sessão por cookie.
- [ ] Cookie de sessão `SameSite=Lax` (mínimo) ou `Strict`; `Secure`.
- [ ] Cada `csrf_exempt` justificado: webhook com assinatura HMAC validada, ou API só com token `Authorization` (não cookie).
- [ ] CORS não reflete `Origin` arbitrário com `Access-Control-Allow-Credentials: true`.
- [ ] Login, logout e troca de e-mail/senha também protegidos (login CSRF).

### Teste

Página HTML local com `<form action="https://alvo/acao" method="POST">` auto-submetida estando logado no alvo; ou `curl` repetindo a requisição sem token e com `Origin: https://evil.example`. Se passar, é achado.

---

## SSRF — Server-Side Request Forgery (CWE-918, dentro de A01:2025)

O servidor busca uma URL controlada pelo atacante e alcança rede interna, metadados da nuvem (`169.254.169.254`), Redis, painéis administrativos.

### Onde procurar

Qualquer lugar em que o servidor faz requisição para endereço vindo de fora:

- Webhooks configuráveis pelo cliente, "importar de URL", preview de link, fetch de avatar/imagem por URL, proxies de imagem, geração de PDF a partir de HTML (o renderizador busca `<img src>` e `<iframe>`), integrações OAuth/OIDC com `discovery URL` configurável, parsers XML (XXE → SSRF), conversores de documentos.
- Python: `requests.get(`, `httpx.`, `urllib.request.urlopen(`, `aiohttp`. Node: `fetch(`, `axios(`, `got(`, `http.request(`. Java: `RestTemplate`, `WebClient`, `URL.openStream`. PHP: `file_get_contents($url)`, `curl_exec`.

### Checklist

- [ ] URL de destino validada **após resolução DNS**: bloquear loopback, RFC1918, link-local (`169.254.0.0/16`, `fe80::/10`), `0.0.0.0`, `::1`, IPv4 mapeado em IPv6, e checar de novo o IP efetivamente conectado (defesa contra DNS rebinding).
- [ ] Redirecionamentos desligados ou revalidados a cada salto (`allow_redirects=False`; atenção ao **urllib3 CVE-2025-50181**, em que desligar redirect no `PoolManager` não funcionava — urllib3 ≥ 2.5.0).
- [ ] Só `http`/`https`; recusar `file://`, `gopher://`, `dict://`, `ftp://`.
- [ ] AWS: IMDSv2 obrigatório (`HttpTokens=required`), hop limit 1 em container.
- [ ] Egress da rede do app restrito (firewall/security group) — a defesa que sobrevive a bug no código.
- [ ] Resposta do fetch não é devolvida crua ao usuário.

### Teste

Apontar o campo de URL para um coletor próprio para confirmar que o servidor busca; depois `http://127.0.0.1:<porta>`, `http://169.254.169.254/latest/meta-data/`, `http://[::ffff:127.0.0.1]/`, `http://0x7f000001/`, e um domínio próprio que redirecione para `127.0.0.1`.

### Casos reais

- **axios CVE-2025-27152**: URL absoluta passada a instância com `baseURL` ignora o `baseURL` → SSRF e vazamento de credenciais; corrigido em 1.8.2.
- **Next.js CVE-2024-34351**: SSRF em Server Actions via header `Host`; **CVE-2025-57822**: SSRF quando middleware repassa headers do request em `NextResponse.next()`.
- **Next.js 2026**: GHSA-c4j6-fc7j-m34r (SSRF no upgrade de WebSocket do servidor Node self-hosted, lote de maio), GHSA-p9j2-gv94-2wf4 (SSRF em `rewrites` com destino controlável) e GHSA-89xv-2m56-2m9x (SSRF em Server Actions com custom server), lote de julho/2026, corrigidos em 15.5.21 / 16.2.11.
- **Capital One (2019)**: SSRF em WAF → credenciais IAM do metadata → 100 milhões de registros. Motivo do IMDSv2.
