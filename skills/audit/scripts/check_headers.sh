#!/usr/bin/env bash
set -uo pipefail

URL="${1:?uso: check_headers.sh https://alvo-autorizado}"
URL="${URL%/}"
UA="security-audit-check/1.0"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
K=(); [ "${INSECURE:-0}" = "1" ] && K=(-k)
c() { curl -sS -A "$UA" "${K[@]}" "$@"; }

ok()   { printf '  [ok]    %s\n' "$1"; }
bad()  { printf '  [FALHA] %s\n' "$1"; }
warn() { printf '  [aviso] %s\n' "$1"; }

c -o /dev/null -D "$TMP/h" --max-time 15 "$URL/" || { echo "Não consegui acessar $URL"; exit 1; }
H="$(tr -d '\r' < "$TMP/h" | awk 'BEGIN{IGNORECASE=1} /^HTTP\//{buf=""} {buf=buf $0 "\n"} END{printf "%s", buf}')"
hget() { printf '%s' "$H" | grep -i "^$1:" | head -n1 | cut -d: -f2- | sed 's/^ *//'; }

echo "== Headers de segurança: $URL"
v="$(hget strict-transport-security)"; [ -n "$v" ] && ok "HSTS: $v" || bad "Strict-Transport-Security ausente"
v="$(hget content-security-policy)"
if [ -z "$v" ]; then bad "Content-Security-Policy ausente"
else
  ok "CSP presente"
  printf '%s' "$v" | grep -q "unsafe-inline" && warn "CSP contém 'unsafe-inline'"
  printf '%s' "$v" | grep -q "unsafe-eval" && warn "CSP contém 'unsafe-eval'"
  printf '%s' "$v" | grep -q "frame-ancestors" || warn "CSP sem frame-ancestors"
fi
v="$(hget x-content-type-options)"; [ "${v,,}" = "nosniff" ] && ok "X-Content-Type-Options: nosniff" || bad "X-Content-Type-Options ausente"
v="$(hget referrer-policy)"; [ -n "$v" ] && ok "Referrer-Policy: $v" || warn "Referrer-Policy ausente"
v="$(hget permissions-policy)"; [ -n "$v" ] && ok "Permissions-Policy presente" || warn "Permissions-Policy ausente"
v="$(hget x-frame-options)"; [ -n "$v" ] && ok "X-Frame-Options: $v" || warn "X-Frame-Options ausente (ok se CSP tem frame-ancestors)"
v="$(hget server)"; [ -n "$v" ] && printf '%s' "$v" | grep -qE '[0-9]' && warn "Server expõe versão: $v"
v="$(hget x-powered-by)"; [ -n "$v" ] && warn "X-Powered-By exposto: $v"
v="$(hget access-control-allow-origin)"; [ "$v" = "*" ] && warn "CORS Access-Control-Allow-Origin: *"

echo "== CORS com origem arbitrária"
C="$(c -o /dev/null -D - --max-time 15 -H 'Origin: https://evil.example' "$URL/" | tr -d '\r')"
if printf '%s' "$C" | grep -qi '^access-control-allow-origin: https://evil.example'; then
  printf '%s' "$C" | grep -qi '^access-control-allow-credentials: true' && bad "Reflete Origin arbitrário COM credenciais" || warn "Reflete Origin arbitrário"
else ok "Não reflete Origin arbitrário na raiz"; fi

echo "== Cookies"
printf '%s' "$H" | grep -i '^set-cookie:' | while IFS= read -r c; do
  name="$(printf '%s' "$c" | cut -d: -f2- | cut -d= -f1 | sed 's/^ *//')"
  miss=""
  printf '%s' "$c" | grep -qi 'secure' || miss+=" Secure"
  printf '%s' "$c" | grep -qi 'httponly' || miss+=" HttpOnly"
  printf '%s' "$c" | grep -qi 'samesite' || miss+=" SameSite"
  [ -z "$miss" ] && ok "cookie $name" || warn "cookie $name sem:$miss"
done

echo "== HTTP → HTTPS"
HOSTPART="${URL#https://}"; HOSTPART="${HOSTPART#http://}"
code="$(c -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 10 "http://$HOSTPART/" 2>/dev/null || true)"
case "$code" in 30[1278]\ https://*) ok "redireciona para HTTPS ($code)";; *) warn "HTTP não redireciona para HTTPS: $code";; esac

echo "== TLS antigo"
for v in tlsv1.0 tlsv1.1; do
  if c -o /dev/null --max-time 8 --"$v" --tls-max "${v#tlsv}" "https://$HOSTPART/" 2>/dev/null; then bad "aceita ${v^^}"; else ok "recusa ${v^^}"; fi
done

echo "== Métodos"
tb="$(c -X TRACE -H 'X-Trace-Probe: eco-7731' --max-time 10 "$URL/" 2>/dev/null || true)"
if printf '%s' "$tb" | grep -q 'eco-7731'; then bad "TRACE ecoa a requisição (Cross-Site Tracing)"
else ok "TRACE não ecoa a requisição"; fi

echo "== Caminhos que não deveriam responder 200"
PATHS=(.git/HEAD .git/config .env .env.local .env.production .DS_Store docker-compose.yml Dockerfile
  backup.zip dump.sql db.sql phpinfo.php server-status actuator actuator/env actuator/heapdump
  __debug__/ debug/pprof/ swagger-ui.html swagger/ openapi.json api-docs api/schema/ graphql
  metrics flower/ .well-known/security.txt)
for p in "${PATHS[@]}"; do
  read -r code size < <(c -o /dev/null -w '%{http_code} %{size_download}' --max-time 10 "$URL/$p" 2>/dev/null || echo "000 0")
  if [ "$p" = ".well-known/security.txt" ]; then
    [ "$code" = "200" ] && ok "security.txt publicado" || warn "security.txt ausente (recomendado, RFC 9116)"
  elif [ "$code" = "200" ]; then
    bad "/$p → 200 ($size bytes) — conferir conteúdo"
  fi
done

echo "== Introspecção GraphQL"
gc="$(c --max-time 10 -H 'Content-Type: application/json' -d '{"query":"{__schema{queryType{name}}}"}' "$URL/graphql" 2>/dev/null || true)"
printf '%s' "$gc" | grep -q '__schema' && bad "introspecção GraphQL aberta em /graphql" || ok "sem introspecção aberta em /graphql"

echo "== Source maps"
c --max-time 15 "$URL/" 2>/dev/null | grep -oE 'src="[^"]+\.js"' | head -n 5 | sed -E 's/src="([^"]+)"/\1/' | while read -r js; do
  case "$js" in http*) full="$js";; //*) full="https:$js";; /*) full="$URL$js";; *) full="$URL/$js";; esac
  code="$(c -o /dev/null -w '%{http_code}' --max-time 10 "$full.map" 2>/dev/null)"
  [ "$code" = "200" ] && warn "source map público: $full.map"
done
echo "Concluído."
