#!/usr/bin/env bash
set -uo pipefail

ROOT="${1:-.}"
MAX="${MAX_HITS:-40}"

EXCLUDES=(node_modules .venv venv env .git dist build .next coverage __pycache__ vendor staticfiles .tox site-packages)

if command -v rg >/dev/null 2>&1; then
  RG_ARGS=(-n --no-heading -S --hidden --max-columns 220 --max-columns-preview)
  for d in "${EXCLUDES[@]}"; do RG_ARGS+=(-g "!**/$d/**"); done
  RG_ARGS+=(-g '!*.min.js' -g '!*.min.css' -g '!*.map' -g '!*.lock' -g '!package-lock.json' -g '!*.svg')
  search() { rg "${RG_ARGS[@]}" "$@" "$ROOT" 2>/dev/null; }
else
  GREP_ARGS=(-rnE -I)
  for d in "${EXCLUDES[@]}"; do GREP_ARGS+=(--exclude-dir="$d"); done
  GREP_ARGS+=(--exclude='*.min.js' --exclude='*.min.css' --exclude='*.map' --exclude='*.lock' --exclude='package-lock.json' --exclude='*.svg')
  search() { grep "${GREP_ARGS[@]}" "$@" "$ROOT" 2>/dev/null | cut -c1-260; }
fi

section() {
  local title="$1"; shift
  local args=()
  for pat in "$@"; do args+=(-e "$pat"); done
  local out
  out="$(search "${args[@]}" | sort -u | head -n "$MAX")"
  if [ -n "$out" ]; then
    printf '\n=== %s ===\n%s\n' "$title" "$out"
  fi
}

printf 'Varredura de padrões perigosos em: %s\n' "$(cd "$ROOT" && pwd)"
printf 'Cada linha é um CANDIDATO. Confirmar se a entrada é controlada pelo usuário.\n'

section "XSS: saída sem escape" \
  '\|\s*safe\b' 'mark_safe\(' 'autoescape\s+off' 'format_html\(\s*f["'"'"']' 'SafeString\(' \
  'Markup\(' 'render_template_string\(' 'dangerouslySetInnerHTML' 'v-html' 'bypassSecurityTrust' \
  '\.innerHTML\s*=' '\.outerHTML\s*=' 'insertAdjacentHTML' 'document\.write\(' '\{!!.*!!\}' '\.html_safe' 'raw\('

section "Execução dinâmica / SSTI / desserialização" \
  '\beval\(' 'new Function\(' 'pickle\.loads?\(' 'yaml\.load\(' 'yaml\.unsafe_load' \
  'ObjectInputStream' '\bunserialize\(' 'node-serialize' 'marshal\.loads' 'jsonpickle\.decode'

section "SQL cru / injeção em ORM" \
  '\.raw\(' '\.extra\(' 'RawSQL\(' 'cursor\.execute\(\s*f["'"'"']' 'execute\(\s*["'"'"'].*%\s' \
  'execute\(.*\.format\(' 'text\(\s*f["'"'"']' 'literal_column\(' '\$queryRawUnsafe' '\$executeRawUnsafe' \
  'knex\.raw\(`' 'sequelize\.query\(`' 'whereRaw\(' 'DB::raw\(' 'nativeQuery\s*=\s*true' \
  'order_by\(\s*request\.' 'filter\(\*\*request' 'annotate\(\*\*' 'Q\(\*\*'

section "Comando de sistema" \
  'os\.system\(' 'shell\s*=\s*True' 'subprocess\.(call|run|Popen)\(\s*f["'"'"']' 'child_process' \
  '\bexec\(\s*`' 'Runtime\.getRuntime\(\)\.exec' 'shell_exec\(' 'passthru\('

section "XML (possível XXE)" \
  'etree\.(parse|fromstring|XMLParser)' 'xml\.dom\.minidom' 'xml\.sax' 'resolve_entities\s*=\s*True' \
  'DocumentBuilderFactory' 'SAXParserFactory' 'XMLInputFactory' 'LIBXML_NOENT' 'noent:\s*true'

section "SSRF: requisição a URL possivelmente externa" \
  'requests\.(get|post|request)\(\s*(url|request\.|data\[|params)' 'urlopen\(' 'httpx\.(get|post)\(\s*(url|request\.)' \
  'axios\.(get|post)\(\s*(req\.|url)' 'fetch\(\s*(req\.|url|body\.)' 'file_get_contents\(\s*\$' \
  'allow_redirects\s*=\s*True'

section "TLS desligado" \
  'verify\s*=\s*False' 'rejectUnauthorized:\s*false' 'NODE_TLS_REJECT_UNAUTHORIZED' 'InsecureSkipVerify:\s*true' \
  'CERT_NONE' 'check_hostname\s*=\s*False'

section "CSRF / CORS" \
  'csrf_exempt' 'csrf\(\)\.disable' 'AbstractHttpConfigurer::disable' 'CORS_ALLOW_ALL_ORIGINS\s*=\s*True' \
  'CORS_ORIGIN_ALLOW_ALL\s*=\s*True' 'Access-Control-Allow-Origin.*\*' 'origin:\s*(true|\*)'

section "Autorização: busca por ID sem escopo (revisar dono/tenant)" \
  'objects\.get\(\s*(pk|id)\s*=' 'get_object_or_404\(\s*\w+\s*,\s*(pk|id)\s*=' 'objects\.all\(\)' \
  'AllowAny' 'fields\s*=\s*["'"'"']__all__' 'findById\(\s*req\.' 'findByPk\(\s*req\.' 'Model::find\(\s*\$' \
  'permit!' 'guarded\s*=\s*\[\]' 'Object\.assign\(\s*\w+\s*,\s*req\.body'

section "Supabase / RLS" \
  'service_role' 'SUPABASE_SERVICE_ROLE' 'create table' 'disable row level security' 'user_metadata' \
  'security\s+definer'

section "Autenticação / tokens" \
  'algorithms\s*=\s*\[.*none' 'verify_signature["'"'"']?\s*:\s*False' 'jwt\.decode\([^)]*verify\s*=\s*False' \
  "algorithm[s]?:\s*\[?['\"]none" 'md5\(' 'sha1\(' 'hashlib\.(md5|sha1)\(' 'random\.(random|randint|choice)\(' \
  'Math\.random\(' 'HTTP_HOST' 'get_host\(\)' 'request\.host'

section "Configuração de produção" \
  'DEBUG\s*=\s*True' 'debug\s*=\s*True' 'APP_DEBUG\s*=\s*true' 'ALLOWED_HOSTS\s*=\s*\[\s*["'"'"']\*' \
  'productionBrowserSourceMaps:\s*true' 'management\.endpoints\.web\.exposure\.include\s*=\s*\*' \
  'SESSION_COOKIE_SECURE\s*=\s*False' 'CSRF_COOKIE_SECURE\s*=\s*False' 'HTTP_X_FORWARDED_FOR' \
  '0\.0\.0\.0:(5432|6379|5672|15672|3306|27017|9200|11211)' '^\s*-\s*["'"'"']?(5432|6379|5672|15672|3306|27017|9200):'

section "Exceção engolida (fail open)" \
  'except\s*:\s*pass' 'except Exception\s*:\s*pass' 'catch\s*\(\w*\)\s*\{\s*\}' 'catch\s*\{\s*\}'

section "Segredos (valor mascarado na revisão; nunca copiar para fora)" \
  'AKIA[0-9A-Z]{16}' 'sk_live_[0-9a-zA-Z]{10,}' 'ghp_[0-9A-Za-z]{30,}' 'xox[baprs]-[0-9A-Za-z-]{10,}' \
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' 'AIza[0-9A-Za-z_-]{35}' \
  '(SECRET_KEY|API_KEY|PASSWORD|TOKEN)\s*=\s*["'"'"'][^"'"'"'$\{]{12,}'

section "Supply chain: Actions sem SHA e scripts de instalação" \
  'uses:\s*[^@]+@(v[0-9]|main|master)' 'pull_request_target' '"(pre|post)install"\s*:'

printf '\nArquivos sensíveis presentes na árvore:\n'
find "$ROOT" \( -path '*/node_modules' -o -path '*/.git' -o -path '*/.venv' -o -path '*/venv' \) -prune -o \
  -type f \( -name '.env' -o -name '.env.*' -o -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' \
  -o -name '*.sql' -o -name '*.dump' -o -name '*.bak' -o -name 'credentials' \) -print 2>/dev/null | head -n "$MAX"

printf '\nArquivos .env rastreados pelo git (devem ser só exemplos sem valor real):\n'
git -C "$ROOT" ls-files 2>/dev/null | grep -E '(^|/)\.env' || printf '(nenhum)\n'
